defmodule Ouroboros do
  @moduledoc """
  A BEAM-native coding-agent runtime.

  Ouroboros treats an agent as supervised state plus typed messages. `Ouroboros.Mesh`
  is the public runtime entry point; Jido supplies the pure agent/action/signal
  primitives, while Ouroboros owns distributed placement, team coordination, durable
  execution policy, and controlled code evolution.
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
      coding_tasks:
        safe_value(&Ouroboros.CodingSession.list/0, [])
        |> normalize_list()
        |> Enum.map(fn task ->
          Map.take(task, [:id, :node, :provider, :status, :created_at, :updated_at])
        end),
      interactive_sessions:
        safe_value(&Ouroboros.InteractiveSession.list/0, [])
        |> normalize_list()
        |> Enum.map(fn session ->
          Map.take(session, [:id, :node, :provider, :status, :created_at, :updated_at])
        end),
      teams:
        safe_value(&Ouroboros.Team.Store.list/0, [])
        |> normalize_list()
        |> Enum.map(fn team ->
          %{
            id: team.id,
            status: team.status,
            worker_count: map_size(team.workers),
            delegation_count: map_size(team.delegations),
            updated_at: team.updated_at
          }
        end),
      orchestration_plans:
        case safe_value(
               &Ouroboros.Orchestration.Scheduler.list/0,
               {:error, :unavailable}
             ) do
          {:ok, plans} ->
            Enum.map(plans, fn plan ->
              %{
                id: plan.id,
                status: plan.status,
                version: plan.version,
                step_count: map_size(plan.steps),
                updated_at: plan.updated_at
              }
            end)

          _other ->
            []
        end,
      control: control_status(),
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

  @doc "Returns the normalized coding-provider capabilities this runtime serves."
  @spec providers() :: [Jido.Harness.AdapterSpec.t()]
  def providers, do: Enum.reject(Jido.Harness.providers(), &(&1.provider == :codex))

  @doc "Probes one coding provider's installation and compatibility."
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

  defp control_status do
    runs =
      case safe_value(&Ouroboros.Control.Store.list/0, {:error, :unavailable}) do
        {:ok, values} ->
          Enum.map(values, fn run ->
            Map.take(run, [
              :id,
              :status,
              :revision,
              :max_revisions,
              :decision,
              :created_at,
              :updated_at
            ])
          end)

        _other ->
          []
      end

    %{runs: runs}
  end

  defp normalize_list(value) when is_list(value), do: value
  defp normalize_list(_value), do: []

  defp availability do
    %{
      cluster: process_group_state([Ouroboros.Cluster]),
      mesh: process_group_state([Ouroboros.Mesh.Directory]),
      coding:
        process_group_state([
          Ouroboros.Coding.Store,
          Ouroboros.Coding.Registry,
          Ouroboros.Coding.TaskSupervisor,
          Ouroboros.Coding.Recovery
        ]),
      interactive:
        process_group_state([
          Ouroboros.Interactive.Store,
          Ouroboros.Interactive.Registry,
          Ouroboros.Interactive.TaskSupervisor,
          Ouroboros.Interactive.Recovery
        ]),
      teams:
        process_group_state([
          Ouroboros.Team.Store,
          Ouroboros.Team.Registry,
          Ouroboros.Team.Supervisor,
          Ouroboros.Team.Recovery
        ]),
      orchestration:
        if(Application.get_env(:ouroboros, :automation_enabled, true),
          do:
            process_group_state([
              Ouroboros.Orchestration.Store,
              Ouroboros.Orchestration.Scheduler
            ]),
          else: :disabled
        ),
      control:
        if(
          Application.get_env(:ouroboros, :automation_enabled, true) and
            Application.get_env(:ouroboros, :control_enabled, false),
          do: process_group_state([Ouroboros.Control.Store, Ouroboros.Control.Server]),
          else: :disabled
        ),
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
