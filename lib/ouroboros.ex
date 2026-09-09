defmodule Ouroboros do
  @moduledoc """
  A BEAM-native coding-agent runtime.

  Ouroboros treats an agent as supervised state plus typed messages. `Ouroboros.Mesh`
  is the public runtime entry point; Jido supplies the pure agent/action/signal
  primitives, while Ouroboros owns durable sessions, distributed placement, and
  controlled code evolution.
  """

  @doc "Returns a snapshot of the local runtime and connected BEAM cluster."
  @spec status() :: map()
  def status do
    %{
      node: node(),
      # The role is what makes the rest of this snapshot legible: a `:builder` or
      # `:signer` node reports most planes `:unavailable` because it never started them,
      # which is a posture rather than a fault.
      role: Ouroboros.Cluster.role(),
      connected_nodes: Node.list(),
      cluster: safe_value(&Ouroboros.Cluster.status/0, %{mode: :unavailable}),
      availability: availability(),
      agents: safe_value(&Ouroboros.Mesh.list_agents/0, []),
      interactive_sessions:
        safe_value(&Ouroboros.InteractiveSession.list/0, [])
        |> normalize_list()
        |> Enum.map(fn session ->
          Map.take(session, [:id, :node, :provider, :status, :created_at, :updated_at])
        end),
      effect_ledger:
        safe_value(
          &Ouroboros.Agent.EffectLedger.status/0,
          %{
            durability: :unavailable,
            retained: 0,
            in_flight: 0,
            ambiguous: 0,
            retention_limit: nil,
            next_sequence: nil
          }
        ),
      upgrade: safe_value(&Ouroboros.Upgrade.NodeExecutor.status/0, %{mode: :unavailable}),
      release: safe_value(&Ouroboros.Release.Runtime.status/0, %{mode: :unavailable}),
      forge:
        safe_value(
          &Ouroboros.Runtime.Exposure.forge_status/0,
          %{signer: :unknown, admit_possible?: false, live_count: 0, live: []}
        )
    }
  end

  @doc "Returns the normalized provider capabilities this runtime serves."
  @spec providers() :: [Jido.Harness.AdapterSpec.t()]
  def providers, do: Enum.reject(Jido.Harness.providers(), &(&1.provider == :codex))

  @doc "Probes one provider's installation and compatibility."
  @spec provider_status(atom()) :: {:ok, Jido.Harness.ProviderStatus.t()} | {:error, term()}
  def provider_status(provider), do: Jido.Harness.status(provider)

  @doc "Returns bounded, content-minimized agent-effect history from this node."
  @spec effects(keyword() | map()) ::
          {:ok, [Ouroboros.Agent.EffectLedger.Entry.t()]} | {:error, term()}
  def effects(filters \\ []), do: Ouroboros.Agent.EffectLedger.list(filters)

  @doc "Returns one retained agent effect by its stable effect ID."
  @spec effect(String.t()) ::
          {:ok, Ouroboros.Agent.EffectLedger.Entry.t()} | :not_found | {:error, term()}
  def effect(effect_id), do: Ouroboros.Agent.EffectLedger.get(effect_id)

  defp normalize_list(value) when is_list(value), do: value
  defp normalize_list(_value), do: []

  defp availability do
    %{
      cluster: process_group_state([Ouroboros.Cluster]),
      mesh: process_group_state([Ouroboros.Mesh.Directory]),
      interactive:
        process_group_state([
          Ouroboros.Interactive.Store,
          Ouroboros.Interactive.Registry,
          Ouroboros.Interactive.TaskSupervisor,
          Ouroboros.Interactive.Recovery
        ]),
      effect_ledger: process_group_state([Ouroboros.Agent.EffectLedger]),
      workspace:
        if(Application.get_env(:ouroboros, :workspace_allowed_roots, []) == [],
          do: :disabled,
          else: process_group_state([Ouroboros.Workspace.Manager])
        ),
      hot_upgrade: process_group_state([Ouroboros.Upgrade.NodeExecutor]),
      release: process_group_state([Ouroboros.Release.Runtime])
    }
  end

  defp process_group_state(names) do
    available? =
      Enum.all?(names, fn name ->
        case Process.whereis(name) do
          pid when is_pid(pid) -> Process.alive?(pid)
          nil -> false
        end
      end)

    if available?,
      do: :available,
      else: :unavailable
  end

  defp safe_value(fun, fallback) do
    fun.()
  rescue
    _error -> fallback
  catch
    :exit, _reason -> fallback
    _kind, _reason -> fallback
  end
end
