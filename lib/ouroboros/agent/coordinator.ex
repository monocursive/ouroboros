defmodule Ouroboros.Agent.Coordinator do
  @moduledoc """
  Inspectable Jido state for a supervised team coordinator.

  `Ouroboros.Team.Server` owns execution and delivery. This agent is the typed,
  queryable projection of team membership and delegation outcomes.
  """

  use Jido.Agent,
    name: "ouroboros_team_coordinator",
    description: "Inspectable coordinator state for an Ouroboros coding-agent team",
    schema: [
      role: [type: :string, default: "coordinator"],
      team_id: [type: :any, default: nil],
      coordinator_id: [type: :any, default: nil],
      status: [type: :atom, default: :initializing],
      workers: [type: :map, default: %{}],
      delegations: [type: :map, default: %{}],
      active_count: [type: :non_neg_integer, default: 0],
      terminal_count: [type: :non_neg_integer, default: 0],
      last_event: [type: :any, default: nil],
      error: [type: :any, default: nil]
    ],
    signal_routes: [
      {"ouroboros.team.started", __MODULE__.StartTeam},
      {"ouroboros.team.worker.added", __MODULE__.AddWorker},
      {"ouroboros.team.task.delegated", __MODULE__.DelegateTask},
      {"ouroboros.team.task.finalized", __MODULE__.FinalizeTask}
    ]

  defmodule StartTeam do
    @moduledoc false

    use Jido.Action,
      name: "start_ouroboros_team",
      description: "Initialize a team coordinator projection",
      schema: [
        team_id: [type: :string, required: true],
        coordinator_id: [type: :string, required: true]
      ]

    @impl true
    def run(params, %{agent: agent}) do
      case {agent.state.team_id, agent.state.coordinator_id} do
        {nil, nil} ->
          {:ok,
           %{
             team_id: params.team_id,
             coordinator_id: params.coordinator_id,
             status: :ready,
             last_event: %{type: :team_started, team_id: params.team_id},
             error: nil
           }}

        {owner, coordinator_id}
        when owner == params.team_id and coordinator_id == params.coordinator_id ->
          {:ok,
           %{
             team_id: params.team_id,
             coordinator_id: params.coordinator_id,
             status: :ready,
             last_event: %{type: :team_started, team_id: params.team_id},
             error: nil
           }}

        {owner, _coordinator_id} when owner != params.team_id ->
          {:error, {:coordinator_owner_conflict, params.coordinator_id, owner, params.team_id}}

        {_owner, coordinator_id} ->
          {:error,
           {:coordinator_identity_conflict, params.team_id, coordinator_id, params.coordinator_id}}
      end
    end
  end

  defmodule AddWorker do
    @moduledoc false

    use Jido.Action,
      name: "add_ouroboros_team_worker",
      description: "Record a worker in the coordinator projection",
      schema: [
        worker_id: [type: :string, required: true],
        worker_node: [type: :string, required: true],
        role: [type: :string, required: true],
        hierarchy: [type: :atom, required: true]
      ]

    @impl true
    def run(params, %{agent: agent}) do
      worker = %{
        id: params.worker_id,
        node: params.worker_node,
        role: params.role,
        hierarchy: params.hierarchy,
        status: :idle
      }

      {:ok,
       %{
         workers: Map.put(agent.state.workers, params.worker_id, worker),
         last_event: %{type: :worker_added, worker_id: params.worker_id},
         error: nil
       }}
    end
  end

  defmodule DelegateTask do
    @moduledoc false

    use Jido.Action,
      name: "delegate_ouroboros_team_task",
      description: "Record a provider-neutral task delegation",
      schema: [
        delegation_id: [type: :string, required: true],
        worker_id: [type: :string, required: true],
        objective: [type: :string, required: true],
        coding_task_id: [type: :string, required: true],
        coding_node: [type: :string, required: true]
      ]

    @impl true
    def run(params, %{agent: agent}) do
      delegation = %{
        id: params.delegation_id,
        worker_id: params.worker_id,
        objective: params.objective,
        coding_task_id: params.coding_task_id,
        coding_node: params.coding_node,
        status: :running,
        result: nil,
        error: nil
      }

      delegations = Map.put(agent.state.delegations, params.delegation_id, delegation)

      {:ok,
       %{
         delegations: delegations,
         active_count: count_active(delegations),
         terminal_count: count_terminal(delegations),
         last_event: %{type: :task_delegated, delegation_id: params.delegation_id},
         error: nil
       }}
    end

    defp count_active(delegations) do
      Enum.count(delegations, fn {_id, delegation} -> delegation.status == :running end)
    end

    defp count_terminal(delegations) do
      Enum.count(delegations, fn {_id, delegation} -> terminal?(delegation.status) end)
    end

    defp terminal?(status), do: status in [:completed, :failed, :cancelled, :lost]
  end

  defmodule FinalizeTask do
    @moduledoc false

    use Jido.Action,
      name: "finalize_ouroboros_team_task",
      description: "Record a persisted terminal coding result",
      schema: [
        delegation_id: [type: :string, required: true],
        worker_id: [type: :string, required: true],
        status: [type: :atom, required: true],
        result: [type: :any, default: nil],
        error: [type: :any, default: nil]
      ]

    @impl true
    def run(params, %{agent: agent}) do
      delegation =
        agent.state.delegations
        |> Map.get(params.delegation_id, %{
          id: params.delegation_id,
          worker_id: params.worker_id
        })
        |> Map.merge(%{
          status: params.status,
          result: params.result,
          error: params.error
        })

      delegations = Map.put(agent.state.delegations, params.delegation_id, delegation)

      {:ok,
       %{
         delegations: delegations,
         active_count: count_active(delegations),
         terminal_count: count_terminal(delegations),
         last_event: %{
           type: :task_finalized,
           delegation_id: params.delegation_id,
           status: params.status
         },
         error: nil
       }}
    end

    defp count_active(delegations) do
      Enum.count(delegations, fn {_id, delegation} -> delegation.status == :running end)
    end

    defp count_terminal(delegations) do
      Enum.count(delegations, fn {_id, delegation} ->
        delegation.status in [:completed, :failed, :cancelled, :lost]
      end)
    end
  end
end
