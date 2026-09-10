defmodule Ouroboros.Mesh.Supervisor do
  @moduledoc "The local supervision and registry boundary for mesh state owners."
  use Supervisor

  def start_link(opts \\ []), do: Supervisor.start_link(__MODULE__, opts, name: __MODULE__)

  @impl true
  def init(_opts) do
    Supervisor.init(
      [
        {Ouroboros.Application.RegistryOwner, keys: :unique, name: Ouroboros.Mesh.Registry},
        {Task.Supervisor, name: Ouroboros.Mesh.Tasks},
        {DynamicSupervisor, strategy: :one_for_one, name: Ouroboros.Mesh.Agents}
      ],
      strategy: :rest_for_one
    )
  end

  def start_agent(module, opts),
    do:
      DynamicSupervisor.start_child(
        Ouroboros.Mesh.Agents,
        {Ouroboros.Mesh.Server, [agent: module] ++ opts}
      )

  def stop_agent(pid) when node(pid) == node(),
    do: DynamicSupervisor.terminate_child(Ouroboros.Mesh.Agents, pid)

  def whereis(id) do
    case Registry.lookup(Ouroboros.Mesh.Registry, id) do
      [{pid, _module}] -> pid
      [] -> nil
    end
  end

  def list_agents do
    Registry.select(Ouroboros.Mesh.Registry, [{{:"$1", :"$2", :_}, [], [{{:"$1", :"$2"}}]}])
  end
end
