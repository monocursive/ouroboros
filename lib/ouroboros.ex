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
      connected_nodes: Node.list(),
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
      upgrade: safe_value(&Ouroboros.Upgrade.NodeExecutor.status/0, %{mode: :unavailable}),
      release: safe_value(&Ouroboros.Release.Runtime.status/0, %{mode: :unavailable})
    }
  end

  @doc "Returns the normalized coding-provider capabilities exposed by Jido Harness."
  @spec providers() :: [Jido.Harness.AdapterSpec.t()]
  def providers, do: Jido.Harness.providers()

  @doc "Probes one coding provider's installation and compatibility."
  @spec provider_status(atom()) :: {:ok, Jido.Harness.ProviderStatus.t()} | {:error, term()}
  def provider_status(provider), do: Jido.Harness.status(provider)

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

    %{enabled: Process.whereis(Ouroboros.Control.Server) != nil, runs: runs}
  end

  defp normalize_list(value) when is_list(value), do: value
  defp normalize_list(_value), do: []

  defp availability do
    %{
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
        process_group_state([
          Ouroboros.Orchestration.Store,
          Ouroboros.Orchestration.Scheduler
        ]),
      control:
        if(Application.get_env(:ouroboros, :control_enabled, false),
          do: process_group_state([Ouroboros.Control.Store, Ouroboros.Control.Server]),
          else: :disabled
        ),
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
