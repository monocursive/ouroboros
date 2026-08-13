defmodule Ouroboros.Application.RegistryOwner do
  @moduledoc false

  use GenServer

  # A Registry supervisor can report its own death before its named partition has
  # finished terminating. Restarting it immediately spins on :already_started and
  # can exhaust the parent supervisor's restart intensity. Keep that race inside a
  # tiny ownership boundary and only let rest_for_one proceed after cleanup has had
  # a scheduler turn.
  @cleanup_delay_ms 25

  def child_spec(opts) do
    name = Keyword.fetch!(opts, :name)

    %{
      id: {__MODULE__, name},
      start: {__MODULE__, :start_link, [opts]},
      type: :supervisor,
      shutdown: :infinity
    }
  end

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    parent = opts |> Keyword.get(:parent, List.first(Process.get(:"$ancestors")))
    registry_opts = Keyword.delete(opts, :parent)

    case Registry.start_link(registry_opts) do
      {:ok, registry} -> {:ok, %{parent: parent, registry: registry}}
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_info({:EXIT, registry, reason}, %{registry: registry} = state) do
    Process.sleep(@cleanup_delay_ms)
    {:stop, {:registry_exited, reason}, %{state | registry: nil}}
  end

  def handle_info({:EXIT, parent, reason}, %{parent: parent} = state),
    do: {:stop, reason, state}

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, %{registry: registry}) when is_pid(registry) do
    if Process.alive?(registry) do
      try do
        Supervisor.stop(registry, :shutdown, :infinity)
      catch
        :exit, _reason -> :ok
      end
    end

    :ok
  end

  def terminate(_reason, _state), do: :ok
end

defmodule Ouroboros.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children =
      [
        Ouroboros.Jido,
        %{
          id: Ouroboros.Mesh.Scope,
          start: {:pg, :start_link, [Ouroboros.Mesh.Scope]},
          type: :worker
        },
        Ouroboros.Mesh.Directory,
        Ouroboros.Upgrade.NodeExecutor,
        Ouroboros.Upgrade.Rollout.Registry,
        Ouroboros.Coding.Store,
        Ouroboros.Interactive.Store,
        Ouroboros.Team.Store,
        Ouroboros.Orchestration.Store,
        Ouroboros.Control.Store,
        Ouroboros.Control.Grants,
        release_runtime()
      ] ++
        workspace_children() ++
        [
          {Ouroboros.Application.RegistryOwner, keys: :unique, name: Ouroboros.Coding.Registry},
          {DynamicSupervisor, strategy: :one_for_one, name: Ouroboros.Coding.TaskSupervisor},
          Ouroboros.Coding.Recovery,
          {Ouroboros.Application.RegistryOwner,
           keys: :unique, name: Ouroboros.Interactive.Registry},
          {DynamicSupervisor, strategy: :one_for_one, name: Ouroboros.Interactive.TaskSupervisor},
          Ouroboros.Interactive.Recovery,
          {Ouroboros.Application.RegistryOwner, keys: :unique, name: Ouroboros.Team.Registry},
          {DynamicSupervisor, strategy: :one_for_one, name: Ouroboros.Team.Supervisor},
          Ouroboros.Team.Recovery,
          orchestration_scheduler()
        ] ++ control_children()

    # Child order is a recovery boundary. If an in-memory authority such as the
    # workspace lease manager or a registry/supervisor disappears, every
    # downstream owner must restart and rebuild from its durable checkpoint.
    # Letting those owners continue under a fresh empty authority would bypass
    # leases or strand sessions.
    #
    # The capability rollout registry sits immediately after the node executor for the
    # same reason: it is the deployment-level record of code the executor loaded, so it
    # must not outlive the executor whose journal it describes.
    Supervisor.start_link(children, strategy: :rest_for_one, name: Ouroboros.Supervisor)
  end

  defp workspace_children do
    case Application.get_env(:ouroboros, :workspace_allowed_roots, []) do
      [_ | _] -> [{Ouroboros.Workspace, recover_reservations: true}]
      [] -> []
    end
  end

  defp orchestration_scheduler do
    opts =
      [
        max_concurrency: Application.get_env(:ouroboros, :orchestration_max_concurrency, 4)
      ]

    opts =
      case Application.get_env(:ouroboros, :orchestration_team_id) do
        team_id when is_binary(team_id) and byte_size(team_id) > 0 ->
          Keyword.put(opts, :executor, {
            Ouroboros.Orchestration.TeamExecutor,
            [
              team_id: team_id,
              worker_id: Application.get_env(:ouroboros, :orchestration_worker_id),
              coding_options: Application.get_env(:ouroboros, :orchestration_coding_options, [])
            ]
          })

        _other ->
          opts
      end

    {Ouroboros.Orchestration.Scheduler, opts}
  end

  defp control_children do
    if Application.get_env(:ouroboros, :control_enabled, false) do
      [
        {Ouroboros.Control.Server,
         [
           store: Ouroboros.Control.Store,
           scheduler: Ouroboros.Orchestration.Scheduler,
           planner: Application.fetch_env!(:ouroboros, :control_planner),
           evaluator: Application.fetch_env!(:ouroboros, :control_evaluator),
           poll_interval: Application.get_env(:ouroboros, :control_poll_interval, 1_000)
         ]}
      ]
    else
      []
    end
  end

  defp release_runtime do
    {Ouroboros.Release.Runtime,
     [
       storage:
         Application.get_env(
           :ouroboros,
           :release_storage,
           {Jido.Storage.ETS, table: :ouroboros_releases}
         ),
       adapter:
         Application.get_env(
           :ouroboros,
           :release_handler_adapter,
           Ouroboros.Release.HandlerAdapter.OTP
         ),
       authorizer:
         Application.get_env(
           :ouroboros,
           :release_authorizer,
           Ouroboros.Release.Authorizer.Deny
         )
     ]}
  end
end
