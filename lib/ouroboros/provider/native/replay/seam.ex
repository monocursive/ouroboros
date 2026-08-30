defmodule Ouroboros.Provider.Native.Replay.Seam do
  @moduledoc """
  Whether the loop this build ships actually honours the replay seams, asked rather than
  assumed.

  R1 defined `tool_source` on the `Loop` struct and documented it as "anything but `:live`
  means the recorded `tool_result` content is authoritative", but wired it only into the
  *inference* ledger gate. The tool dispatch path — `dispatch/2`, `open_tool_effect/5`,
  `settle_tool_effect/4` — does not read the field, so a replay that ran a tool-calling
  turn through the shipped loop would dispatch the tool for real and write a `:tool_call`
  ledger entry for it. Both are precisely what verified replay must never do.

  The engine therefore asks the loop, once per VM, instead of carrying a constant somebody
  has to remember to flip: it runs one throwaway turn whose only tool call names a tool
  that does not exist, with a recorded result staged for it under the `tool_source` field.
  If the recorded content comes back, the seam is live. If the loop's "unknown tool"
  message comes back, it is not — and nothing ran either way, which is what makes this
  probe safe to run against a loop that ignores the field.

  The probe writes nothing: no journal (`journal: nil`), no checkpoint (`checkpoint: nil`),
  no session directory, and no ledger entry — the inference half of `tool_source` *is*
  wired, so the model call is not gated, and an unknown tool never opens a tool effect.
  """

  alias Ouroboros.Provider.Native.Hooks
  alias Ouroboros.Provider.Native.Loop
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Replay.Model, as: ReplayModel

  require Logger

  @cache {__MODULE__, :tool_dispatch}

  # A name `Tools.lookup/3` can never resolve, so the live path cannot execute anything
  # even if the seam is absent.
  @probe_tool "__replay_seam_probe__"
  @probe_output "ouroboros.replay.seam.probe"

  @doc """
  Whether `Loop` answers a tool call from `tool_source` instead of dispatching it.

  Memoised in `:persistent_term` for the life of the VM: the answer is a property of the
  compiled loop, and a replay of a long session would otherwise pay for one throwaway turn
  per turn it verifies.
  """
  @spec tool_dispatch_honored?() :: boolean()
  def tool_dispatch_honored? do
    case :persistent_term.get(@cache, :unknown) do
      :unknown ->
        answer = probe()
        :persistent_term.put(@cache, answer)
        answer

      known ->
        known
    end
  end

  @doc "Forgets the memoised answer. For tests that want the probe itself under test."
  @spec forget() :: :ok
  def forget do
    _ = :persistent_term.erase(@cache)
    :ok
  end

  @doc """
  The value the engine puts in `tool_source`.

  A tagged tuple rather than a closure, because R1's own words are "anything but `:live`
  means the recorded content is authoritative" — data, not behaviour. If the seam lands
  in another shape the probe simply answers `false` and the engine bounds a tool-calling
  turn by name; it never falls through to dispatching one.
  """
  @spec tool_source(%{optional(String.t()) => map()}) :: {:recorded, map()}
  def tool_source(results) when is_map(results), do: {:recorded, results}

  defp probe do
    root =
      Path.join(System.tmp_dir!(), "ouroboros-replay-seam-#{System.unique_integer([:positive])}")

    try do
      File.mkdir_p!(root)

      with {:ok, scope} <- Paths.scope(root, [], :read_only) do
        {:ok, state} = run(scope)
        Enum.any?(state.messages, &(Map.get(&1, :role) == :tool and &1.content == @probe_output))
      else
        _unscopable -> false
      end
    rescue
      error ->
        Logger.debug("replay seam probe failed (#{Exception.message(error)}); assuming absent")
        false
    catch
      _kind, _reason -> false
    after
      File.rm_rf(root)
    end
  end

  defp run(scope) do
    ReplayModel.install(
      [
        %{
          iteration: 1,
          seq: 1,
          at: nil,
          turn_id: "seam-probe",
          request_sha256: nil,
          chunks: [{:tool_call, %{id: "probe", name: @probe_tool, input: %{}}}]
        },
        %{
          iteration: 2,
          seq: 2,
          at: nil,
          turn_id: "seam-probe",
          request_sha256: nil,
          chunks: [{:text, "done"}, {:finish, :stop}]
        }
      ],
      ReplayModel
    )

    result =
      Loop.run_turn(
        %Loop{
          emit: fn _event -> :ok end,
          model_module: ReplayModel,
          model_spec: "replay:seam-probe",
          system: "probe",
          scope: scope,
          session_dir: nil,
          session_id: nil,
          provider_session_id: "replay-seam-probe",
          turn_id: "seam-probe",
          approval_mode: :auto_approve,
          hooks: %Hooks{workspace: scope.root},
          journal: nil,
          checkpoint: nil,
          max_iterations: 4,
          tool_source: tool_source(%{"probe" => %{output: @probe_output, is_error: false}}),
          control_feed: fn state -> state end
        },
        "probe"
      )

    ReplayModel.uninstall()
    result
  end
end
