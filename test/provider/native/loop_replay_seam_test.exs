defmodule Ouroboros.Provider.Native.LoopReplaySeamTest do
  @moduledoc """
  The `tool_source` seam at the loop's own level: replay executes nothing and accounts for
  nothing.

  `replay_parity_test.exs` proves a replayed turn *reads* like the turn it replays. This
  file proves the two things that must be true underneath that, and which a parity
  assertion cannot see: the tool did not run, and no ledger entry was written for it. Both
  are asserted against a tool whose execution leaves physical evidence — a `write` that
  would put a file on disk — because "the output matched the record" is exactly what a
  loop that re-ran the tool would also report.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Provider.Native.Hooks
  alias Ouroboros.Provider.Native.Loop
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Test.NativeModelScript

  setup do
    root = Path.join(System.tmp_dir!(), "native-seam-#{System.unique_integer([:positive])}")
    File.mkdir_p!(Path.join(root, "workspace/lib"))
    File.mkdir_p!(Path.join(root, "session"))
    on_exit(fn -> File.rm_rf(root) end)

    {:ok, scope} = Paths.scope(Path.join(root, "workspace"), [], :workspace_write)

    session_id = "seam-sess-#{System.unique_integer([:positive, :monotonic])}"

    %{
      root: root,
      scope: scope,
      # Only the live control uses this. A replay is handed `session_dir: nil` — see
      # `run/2` — and the live path's very first act on a write is to snapshot the file
      # into it, so a replay that reached the tool path would crash rather than quietly
      # write somewhere. That is a fine way for this seam to fail.
      session_dir: Path.join(root, "session"),
      evidence: Path.join(root, "workspace/lib/written.ex"),
      session_id: session_id,
      principal: "session:" <> session_id
    }
  end

  describe "a recorded tool is answered, never run" do
    test "the tool leaves no trace, and the record's content is what enters the conversation",
         context do
      {:ok, state, _events} =
        replay(context, %{
          "c1" => %{output: "wrote 2 lines to lib/written.ex", is_error: false}
        })

      # The live turn this replays really would have created the file. This one did not.
      refute File.exists?(context.evidence),
             "the replayed turn executed the tool it was supposed to answer from the record"

      assert %{role: :tool, tool_call_id: "c1", content: "wrote 2 lines to lib/written.ex"} =
               tool_message(state)

      refute tool_message(state).is_error
    end

    test "no tool_call and no inference entry is written for a turn that ran nothing",
         context do
      {:ok, _state, _events} = replay(context, %{"c1" => %{output: "wrote it", is_error: false}})

      assert entries(context, :tool_call) == [],
             "replay wrote a :tool_call entry for an effect that never happened"

      assert entries(context, :inference) == [],
             "replay wrote an :inference entry for a model call it did not make"
    end

    test "the live path still executes and still accounts, so the guards are not a blanket",
         context do
      # The control: the same script with `tool_source: :live` does everything replay did
      # not. Without this the assertions above would also pass on a loop that had simply
      # stopped working.
      {:ok, state, _events} =
        run(context, tool_source: :live, session_dir: context.session_dir)

      assert File.exists?(context.evidence)
      assert tool_message(state).is_error == false
      assert [entry] = entries(context, :tool_call)
      assert entry.attempt.call_id == "c1"

      # One per round-trip: the call that asked for the tool, and the one that answered.
      assert [first, second] = entries(context, :inference)
      assert Enum.sort([first.attempt.iteration, second.attempt.iteration]) == [1, 2]
    end
  end

  describe "the tool_call event" do
    test "carries the recorded ledger_ref rather than a fresh one", context do
      {:ok, _state, events} =
        replay(context, %{
          "c1" => %{
            output: "wrote it",
            is_error: false,
            ledger_ref: "tool-0123456789abcdef0123456789abcdef"
          }
        })

      assert %{"ledger_ref" => ref} = payload_of(events, :tool_call)

      assert ref == %{
               "node" => Atom.to_string(node()),
               "id" => "tool-0123456789abcdef0123456789abcdef"
             }
    end

    test "omits the reference entirely when the record carried none", context do
      {:ok, _state, events} = replay(context, %{"c1" => %{output: "wrote it", is_error: false}})

      # `reject_nils/1` drops the key rather than sending `null`, which is the same shape a
      # live ungated call produces — an absent reference means nothing was recorded, and
      # that is exactly true here.
      refute Map.has_key?(payload_of(events, :tool_call), "ledger_ref")
    end
  end

  describe "a call the record does not hold" do
    test "comes back named, and still runs nothing", context do
      {:ok, state, _events} =
        replay(context, %{"some-other-call" => %{output: "x", is_error: false}})

      refute File.exists?(context.evidence)

      message = tool_message(state)
      assert message.is_error
      assert message.content =~ "not_in_record"
      assert message.content =~ "c1"
      assert entries(context, :tool_call) == []
    end

    test "so does a tool_source shape this build does not understand", context do
      # "Anything but `:live` means the recorded content is authoritative" — a value in an
      # unfamiliar shape is still not a licence to dispatch.
      {:ok, state, _events} = run(context, tool_source: {:some_future_shape, :whatever})

      refute File.exists?(context.evidence)
      assert tool_message(state).is_error
      assert entries(context, :tool_call) == []
      assert entries(context, :inference) == []
    end
  end

  # ------------------------------------------------------------------ helpers

  defp replay(context, results), do: run(context, tool_source: {:recorded, results})

  defp run(context, overrides) do
    {model_spec, _agent} =
      NativeModelScript.start([
        [
          {:text, "writing"},
          {:tool_call,
           %{
             id: "c1",
             name: "write",
             input: %{
               "path" => context.evidence,
               "content" => "defmodule Written do\nend\n"
             }
           }}
        ],
        [{:text, "done"}, {:finish, :stop}]
      ])

    test = self()

    loop =
      struct!(
        %Loop{
          emit: fn event -> send(test, {:event, event}) end,
          model_module: NativeModelScript,
          model_spec: model_spec,
          system: "system",
          scope: context.scope,
          # No session directory, no journal, no checkpoint: a replay writes nothing at all,
          # and a test that gave it somewhere to write would not notice if it did.
          session_dir: nil,
          session_id: context.session_id,
          provider_session_id: "native-seam-test",
          turn_id: "turn-1",
          approval_mode: :auto_approve,
          approval_timeout_ms: 2_000,
          hooks: %Hooks{workspace: context.scope.root},
          journal: nil,
          checkpoint: nil
        },
        overrides
      )

    {:ok, state} = Loop.run_turn(loop, "do the thing")
    {:ok, state, drain()}
  end

  # The loop ran in this process, so every event it emitted is already queued here.
  defp drain(acc \\ []) do
    receive do
      {:event, event} -> drain([event | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  defp tool_message(state), do: Enum.find(state.messages, &(Map.get(&1, :role) == :tool))

  defp payload_of(events, type) do
    case Enum.find(events, &(&1.type == type)) do
      nil -> nil
      event -> event.payload
    end
  end

  defp entries(context, effect) do
    {:ok, entries} = EffectLedger.list(principal: context.principal, effect: effect)
    entries
  end
end
