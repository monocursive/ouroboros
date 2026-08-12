defmodule Ouroboros.Mesh do
  @moduledoc """
  Distribution-native lifecycle and messaging for logical agents.

  Every agent is a supervised Jido process. Local directories join those processes to
  a distributed `:pg` group keyed by logical agent ID, so ordinary Jido calls work
  across connected BEAM nodes. `:global.trans/2` narrows duplicate-start races in a
  healthy connected cluster; it is intentionally not presented as partition-safe
  consensus.
  """

  alias Ouroboros.Mesh.Directory
  alias Ouroboros.Signals.{AgentMessage, TaskAssigned, TaskCompleted}

  @scope Ouroboros.Mesh.Scope

  @type agent_id :: String.t()

  @doc "Starts a logical agent on the local node."
  @spec start_agent(agent_id(), keyword()) :: {:ok, pid()} | {:error, term()}
  def start_agent(id, opts \\ []) when is_binary(id) and is_list(opts) do
    :global.trans({__MODULE__, id}, fn -> do_start_agent(id, opts) end)
  end

  @doc "Starts an agent on a selected connected node."
  @spec start_agent_on(node(), agent_id(), keyword()) :: {:ok, pid()} | {:error, term()}
  def start_agent_on(target_node, id, opts \\ [])
      when is_atom(target_node) and is_binary(id) and is_list(opts) do
    if target_node == node() do
      start_agent(id, opts)
    else
      :erpc.call(target_node, __MODULE__, :start_agent, [id, opts])
    end
  catch
    :error, reason -> {:error, {:remote_start_failed, target_node, reason}}
  end

  @doc "Returns the deterministic live owner for a logical agent ID."
  @spec whereis(agent_id()) :: pid() | nil
  def whereis(id) when is_binary(id) do
    id
    |> members()
    |> Enum.sort_by(fn pid -> {Atom.to_string(node(pid)), inspect(pid)} end)
    |> List.first()
  end

  @doc "Returns every visible process claiming a logical agent ID."
  @spec members(agent_id()) :: [pid()]
  def members(id) when is_binary(id) do
    @scope
    |> :pg.get_members(Directory.group(id))
    |> Enum.filter(&remote_alive?/1)
  catch
    :exit, _ -> []
  end

  @doc "Lists visible logical agents and makes split-brain claims explicit."
  @spec list_agents() :: [
          %{id: agent_id(), pid: pid(), node: node(), replicas: non_neg_integer()}
        ]
  def list_agents do
    @scope
    |> :pg.which_groups()
    |> Enum.flat_map(fn
      {:ouroboros_agent, id} ->
        pids = members(id)

        case deterministic_owner(pids) do
          nil -> []
          pid -> [%{id: id, pid: pid, node: node(pid), replicas: length(pids)}]
        end

      _other ->
        []
    end)
    |> Enum.sort_by(& &1.id)
  catch
    :exit, _ -> []
  end

  @doc "Sends a typed CloudEvents-style message to an agent."
  @spec send_message(agent_id(), agent_id(), term(), keyword()) ::
          {:ok, Jido.Agent.t()} | {:error, term()}
  def send_message(from, to, body, opts \\ [])
      when is_binary(from) and is_binary(to) and is_list(opts) do
    correlation_id = Keyword.get_lazy(opts, :correlation_id, &Jido.Signal.ID.generate!/0)

    with pid when is_pid(pid) <- whereis(to),
         {:ok, signal} <-
           AgentMessage.new(
             %{
               from: from,
               body: body,
               correlation_id: correlation_id,
               causation_id: Keyword.get(opts, :causation_id)
             },
             subject: to,
             source: source_for(from)
           ) do
      Jido.AgentServer.call(pid, signal, Keyword.get(opts, :timeout, 5_000))
    else
      nil -> {:error, {:agent_not_found, to}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "Assigns a task through the same typed message path used across nodes."
  @spec assign_task(agent_id(), agent_id(), String.t(), keyword()) ::
          {:ok, String.t(), Jido.Agent.t()} | {:error, term()}
  def assign_task(from, to, objective, opts \\ [])
      when is_binary(from) and is_binary(to) and is_binary(objective) and is_list(opts) do
    task_id = Keyword.get_lazy(opts, :task_id, &Jido.Signal.ID.generate!/0)
    correlation_id = Keyword.get_lazy(opts, :correlation_id, &Jido.Signal.ID.generate!/0)

    with pid when is_pid(pid) <- whereis(to),
         {:ok, signal} <-
           TaskAssigned.new(
             %{
               from: from,
               task_id: task_id,
               objective: objective,
               correlation_id: correlation_id
             },
             subject: to,
             source: source_for(from)
           ),
         {:ok, agent} <- Jido.AgentServer.call(pid, signal, Keyword.get(opts, :timeout, 5_000)) do
      {:ok, task_id, agent}
    else
      nil -> {:error, {:agent_not_found, to}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "Marks a task complete on its owning agent."
  @spec complete_task(agent_id(), String.t(), term(), keyword()) ::
          {:ok, Jido.Agent.t()} | {:error, term()}
  def complete_task(id, task_id, result, opts \\ [])
      when is_binary(id) and is_binary(task_id) and is_list(opts) do
    with pid when is_pid(pid) <- whereis(id),
         {:ok, signal} <- TaskCompleted.new(%{task_id: task_id, result: result}, subject: id) do
      Jido.AgentServer.call(pid, signal, Keyword.get(opts, :timeout, 5_000))
    else
      nil -> {:error, {:agent_not_found, id}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "Returns the full inspectable Jido process state for an agent."
  @spec state(agent_id()) :: {:ok, Jido.AgentServer.State.t()} | {:error, term()}
  def state(id) when is_binary(id) do
    case whereis(id) do
      nil -> {:error, {:agent_not_found, id}}
      pid -> Jido.AgentServer.state(pid)
    end
  end

  @doc "Stops an agent on the node that owns it."
  @spec stop_agent(agent_id()) :: :ok | {:error, term()}
  def stop_agent(id) when is_binary(id) do
    case whereis(id) do
      nil -> {:error, {:agent_not_found, id}}
      pid when node(pid) == node() -> Ouroboros.Jido.stop_agent(pid)
      pid -> :erpc.call(node(pid), Ouroboros.Jido, :stop_agent, [pid])
    end
  catch
    :error, reason -> {:error, {:remote_stop_failed, reason}}
  end

  @doc "Connects this runtime to another distributed Erlang node."
  @spec connect(node()) :: true | false | :ignored
  def connect(other_node) when is_atom(other_node), do: Node.connect(other_node)

  defp do_start_agent(id, opts) do
    case whereis(id) do
      nil ->
        agent_module = Keyword.get(opts, :agent, Ouroboros.Agent.Worker)

        initial_state =
          opts
          |> Keyword.take([:role, :objective, :parent_id])
          |> Map.new()

        start_opts =
          opts
          |> Keyword.take([:debug, :error_policy, :max_queue_size])
          |> Keyword.merge(id: id, initial_state: initial_state)

        with {:ok, pid} <- Ouroboros.Jido.start_agent(agent_module, start_opts),
             :ok <- Directory.register(id, pid) do
          {:ok, pid}
        end

      pid ->
        {:error, {:already_started, pid}}
    end
  end

  defp deterministic_owner([]), do: nil

  defp deterministic_owner(pids) do
    Enum.min_by(pids, fn pid -> {Atom.to_string(node(pid)), inspect(pid)} end)
  end

  defp remote_alive?(pid) when node(pid) == node(), do: Process.alive?(pid)
  defp remote_alive?(pid), do: node(pid) in Node.list()

  defp source_for(id), do: "/ouroboros/agents/" <> URI.encode(id)
end
