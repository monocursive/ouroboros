defmodule Ouroboros.Mesh do
  @moduledoc """
  Distribution-native lifecycle and messaging for logical agents.

  Every agent is an owned supervised mesh process. Local directories join those processes to
  a distributed `:pg` group keyed by logical agent ID, so ordinary server calls work
  across connected BEAM nodes. `:global.trans/2` narrows duplicate-start races in a
  healthy connected cluster; it is intentionally not presented as partition-safe
  consensus.

  Visibility is eventually consistent. `whereis/1` and `members/1` qualify a remote
  entry by node connectivity, never by remote process liveness, because probing the
  owner would turn every lookup into a network call. A returned pid is an observation,
  not a guarantee: a remote agent can already be dead while `:pg` propagates its leave.
  `whereis/1` may return one of several replicas; mutating and routing functions refuse
  that ambiguity instead of picking a winner. `list_agents/0` already exposes
  `replicas`. The mitigation for a failed or unanswered target is an error tuple
  instead of exiting the caller, so callers must handle
  `{:error, {:agent_call_failed, kind, reason}}`.

  `start_agent/2` is a remote-reachable start surface: `:erpc` from any connected node
  can invoke it and choose the `:agent` module. Startable modules are therefore limited
  to the `Ouroboros.Capability.` namespace — reserved for agents forged at runtime — plus
  the single named module `Ouroboros.Wasm.Capability`, plus whatever
  `:mesh_allowed_agent_modules` names in application config.
  """

  alias Ouroboros.Mesh.Directory
  alias Ouroboros.Mesh.Server
  alias Ouroboros.Mesh.Supervisor, as: MeshSupervisor
  alias Ouroboros.Signals.AgentMessage

  @scope Ouroboros.Mesh.Scope
  @agent_module_prefixes ["Elixir.Ouroboros.Capability."]

  # Lane W adds exactly one startable module, not a namespace (F5).
  # `Ouroboros.Wasm.Capability` is the static wrapper every WebAssembly capability runs
  # inside (docs/WASM.md §7.2); everything else under `Ouroboros.Wasm.` is host machinery —
  # the pool, the store, the verifier, the rollout — and admitting the prefix meant this
  # remote-reachable surface said "start any of them" and was saved only by the accident that
  # none of the others exports `new/0` or `new/1` today. A module added to that namespace
  # tomorrow would silently become startable from any connected node; naming the one module
  # is the same protection that does not depend on what the namespace happens to contain.
  # `test/mesh_test.exs` enumerates the namespace and fails if a second module becomes
  # startable.
  @agent_modules ["Elixir.Ouroboros.Wasm.Capability"]

  @type agent_id :: String.t()
  # A wedged peer must be able to lose a placement or a stop without losing the caller
  # forever; every cross-node call here carries this bound, and `:timeout` is reported
  # as an error tuple like any other transport fault.
  @remote_call_timeout_ms 30_000

  @doc """
  Starts a logical agent on the local node.

  `:agent` names the module to start and carries no default: this runtime defines no
  general-purpose agent, and a caller that named none is asking for something no node can
  answer. `:role`, `:objective`, and `:parent_id` seed agent state. An explicit
  `:initial_state` map is merged over that trio and wins on conflict, so a runtime-defined
  agent can seed schema keys this module does not know about.
  """
  @spec start_agent(agent_id(), keyword()) :: {:ok, pid()} | {:error, term()}
  def start_agent(id, opts \\ []) when is_binary(id) and is_list(opts) do
    agent_module = Keyword.get(opts, :agent)

    # Both checks are pure input validation on a remote-reachable surface, so settle
    # them before taking a cluster-wide lock.
    with :ok <- check_agent_module(agent_module),
         {:ok, initial_state} <- build_initial_state(opts) do
      start_opts = build_start_opts(id, opts, initial_state)

      :global.trans({{__MODULE__, id}, self()}, fn ->
        do_start_agent(id, agent_module, start_opts)
      end)
    end
  end

  @doc """
  Starts an agent on a selected connected node.

  The target is checked before anything is placed on it: it must be connected and must
  be running this runtime in the `:core` role, because a `:builder` or `:signer` node
  runs none of the runtime a placed agent reaches. The check is an
  observation about configuration, not a security boundary — see `Ouroboros.Cluster` —
  and `config :ouroboros, :placement_role_check` turns it off for callers that place
  onto nodes this runtime cannot introspect.
  """
  @spec start_agent_on(node(), agent_id(), keyword()) :: {:ok, pid()} | {:error, term()}
  def start_agent_on(target_node, id, opts \\ [])
      when is_atom(target_node) and is_binary(id) and is_list(opts) do
    case ensure_mesh_placement(target_node) do
      :ok -> place_agent(target_node, id, opts)
      {:error, reason} -> {:error, {:placement_refused, target_node, reason}}
    end
  end

  defp place_agent(target_node, id, opts) do
    if target_node == node() do
      start_agent(id, opts)
    else
      :erpc.call(target_node, __MODULE__, :start_agent, [id, opts], @remote_call_timeout_ms)
    end
  catch
    # `:erpc` reports transport faults as `:error`, but a remote exit arrives as
    # `:exit` and a remote throw as `:throw`. Catching only `:error` let both escape
    # and crash callers that are merely trying to place an agent.
    kind, reason -> {:error, {:remote_start_failed, target_node, {kind, reason}}}
  end

  @doc """
  Returns one visible process for a logical agent ID, if any.

  Observation-only: when `:pg` reports several members, this returns the sorted-first
  replica. Callers that send or mutate must use `whereis_unique/1` or the routing
  functions in this module, so split-brain is an error instead of silent mis-delivery.
  `list_agents/0` already exposes `replicas`.
  """
  @spec whereis(agent_id()) :: pid() | nil
  def whereis(id) when is_binary(id) do
    id
    |> members()
    |> Enum.sort_by(fn pid -> {Atom.to_string(node(pid)), inspect(pid)} end)
    |> List.first()
  end

  @doc """
  Returns the unique visible owner for a logical agent ID.

  Unlike `whereis/1`, two or more members is `{:error, {:ambiguous_replicas, id, count}}`
  rather than an arbitrary pid.
  """
  @spec whereis_unique(agent_id()) :: {:ok, pid()} | {:error, term()}
  def whereis_unique(id) when is_binary(id), do: locate(id)

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
          {:ok, map()} | {:error, term()}
  def send_message(from, to, body, opts \\ [])
      when is_binary(from) and is_binary(to) and is_list(opts) do
    correlation_id = Keyword.get_lazy(opts, :correlation_id, &Ouroboros.ID.generate!/0)

    with {:ok, pid} <- locate(to),
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
      call_agent(pid, signal, Keyword.get(opts, :timeout, 5_000))
    else
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "Returns the owned logical ID and committed domain state for an agent."
  @spec state(agent_id()) :: {:ok, %{agent: %{id: agent_id(), state: map()}}} | {:error, term()}
  def state(id) when is_binary(id) do
    case locate(id) do
      {:ok, pid} -> agent_state(pid)
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "Stops an agent on the node that owns it."
  @spec stop_agent(agent_id()) :: :ok | {:error, term()}
  def stop_agent(id) when is_binary(id) do
    case locate(id) do
      {:error, reason} ->
        {:error, reason}

      {:ok, pid} when node(pid) == node() ->
        MeshSupervisor.stop_agent(pid)

      {:ok, pid} ->
        with :ok <- Ouroboros.Cluster.ensure_compatible(node(pid)) do
          :erpc.call(node(pid), MeshSupervisor, :stop_agent, [pid], @remote_call_timeout_ms)
        end
    end
  catch
    kind, reason -> {:error, {:remote_stop_failed, {kind, reason}}}
  end

  @doc "Connects this runtime to another distributed Erlang node."
  @spec connect(node()) :: true | false | :ignored
  def connect(other_node) when is_atom(other_node), do: Node.connect(other_node)

  defp locate(id) do
    case members(id) do
      [] -> {:error, {:agent_not_found, id}}
      [pid] -> {:ok, pid}
      pids -> {:error, {:ambiguous_replicas, id, length(pids)}}
    end
  end

  defp do_start_agent(id, agent_module, start_opts) do
    case members(id) do
      [] ->
        with {:ok, pid} <- MeshSupervisor.start_agent(agent_module, start_opts) do
          try do
            case Directory.register(id, pid) do
              :ok ->
                {:ok, pid}

              {:error, reason} ->
                MeshSupervisor.stop_agent(pid)
                {:error, reason}
            end
          catch
            kind, reason ->
              MeshSupervisor.stop_agent(pid)
              {:error, {:directory_registration_failed, kind, reason}}
          end
        end

      [pid] ->
        {:error, {:already_started, pid}}

      pids ->
        {:error, {:ambiguous_replicas, id, length(pids)}}
    end
  end

  defp check_agent_module(module) do
    cond do
      not agent_module_allowed?(module) ->
        {:error, {:agent_module_not_allowed, module}}

      Code.ensure_loaded?(module) and function_exported?(module, :init_state, 1) and
          function_exported?(module, :handle_message, 3) ->
        :ok

      true ->
        {:error, {:unsupported_agent_contract, module}}
    end
  end

  defp agent_module_allowed?(module) when is_atom(module) do
    name = Atom.to_string(module)

    String.starts_with?(name, @agent_module_prefixes) or name in @agent_modules or
      module in Application.get_env(:ouroboros, :mesh_allowed_agent_modules, [])
  end

  defp agent_module_allowed?(_module), do: false

  defp build_initial_state(opts) do
    seeded = opts |> Keyword.take([:role, :objective, :parent_id]) |> Map.new()

    case Keyword.get(opts, :initial_state, %{}) do
      explicit when is_map(explicit) -> {:ok, Map.merge(seeded, explicit)}
      other -> {:error, {:invalid_initial_state, other}}
    end
  end

  defp build_start_opts(id, opts, initial_state) do
    opts
    |> Keyword.take([:debug, :error_policy, :max_queue_size])
    |> Keyword.merge(id: id, initial_state: initial_state)
  end

  # Server.call/3 and state/1 are plain GenServer calls, so they exit on
  # timeout, :noproc, and :noconnection. Agent visibility here is eventually
  # consistent and a handler may legitimately outrun the call timeout, which makes
  # those ordinary outcomes rather than caller bugs.
  defp call_agent(pid, signal, timeout) do
    with :ok <- ensure_owner_compatible(pid), do: Server.call(pid, signal, timeout)
  catch
    kind, reason -> {:error, {:agent_call_failed, kind, reason}}
  end

  defp agent_state(pid) do
    with :ok <- ensure_owner_compatible(pid), do: Server.state(pid)
  catch
    kind, reason -> {:error, {:agent_call_failed, kind, reason}}
  end

  defp ensure_owner_compatible(pid) when node(pid) == node(), do: :ok
  defp ensure_owner_compatible(pid), do: Ouroboros.Cluster.ensure_compatible(node(pid))

  defp ensure_mesh_placement(target) do
    with :ok <- Ouroboros.Cluster.ensure_compatible(target),
         :ok <- Ouroboros.Cluster.ensure_placeable(target),
         do: :ok
  end

  defp deterministic_owner([]), do: nil

  defp deterministic_owner(pids) do
    Enum.min_by(pids, fn pid -> {Atom.to_string(node(pid)), inspect(pid)} end)
  end

  defp remote_alive?(pid) when node(pid) == node(), do: Process.alive?(pid)
  defp remote_alive?(pid), do: node(pid) in Node.list()

  defp source_for(id), do: "/ouroboros/agents/" <> URI.encode(id)
end
