defmodule Ouroboros.Provider.Native.Mcp.Pool do
  @moduledoc """
  Owns every MCP server this node runs, keyed by `{workspace_root, server_name}`.

  An MCP server belongs to the runtime, not to a session — two sessions in one workspace
  share one child, which is the difference between a `npx`-launched server starting once
  and starting once per turn. Sessions take a ref-counted claim; the pool monitors the
  claimant, so **a session that ends releases its claim without anyone noticing, and the
  last claim released stops the child.** That is the clean kill on session end: not a
  timer, not a sweep, the monitor.

  Failure is a state, not an exception. A server that dies is restarted with backoff up
  to `max_restarts`; past that the key is marked `:broken` for `broken_ms` and every call
  against it answers `{:error, :broken}` immediately, so a server that fails on every
  spawn is not respawned on every turn. Nothing here raises into a caller and nothing
  here blocks: requests are issued by the caller's own process against a pid this pool
  hands out, so one slow server cannot stall the pool's mailbox — and neither can a
  handshake, because the pool only ever *starts* a server and lets the caller wait.

  The pool checkpoints nothing. On restart every server is gone and the next session
  spawns fresh, because the only truth is the configuration on disk.
  """

  use GenServer

  require Logger

  alias Ouroboros.Provider.Native.Mcp.Config
  alias Ouroboros.Provider.Native.Mcp.Server
  alias Ouroboros.Provider.Native.Mcp.Servers

  @call_timeout 5_000

  @typedoc "One server's key: the workspace it was configured for, and its name."
  @type key :: {String.t() | nil, String.t()}

  @typedoc "What `ensure/3` reports for one configured server."
  @type placement :: %{
          name: String.t(),
          key: key(),
          state: :starting | :ready | :broken | :restarting,
          pid: pid() | nil
        }

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc """
  Starts every definition that is not already running for `workspace_root`, and reports
  where each one stands.

  Never waits for a handshake. A caller that needs a ready server waits on the pid this
  returns, in its own process.
  """
  @spec ensure(GenServer.server(), String.t() | nil, [Servers.t()]) :: [placement()]
  def ensure(pool, workspace_root, definitions) do
    case call(pool, {:ensure, workspace_root, definitions}) do
      {:error, _reason} -> []
      placements -> placements
    end
  end

  @doc """
  Claims the server named `name` for `owner`, starting it if this is the first claim.

  The claim is released when the owner dies. `owner` may be `nil` — a caller with no
  session process behind it, such as the tool-spec build at the start of a turn — and
  then only the idle clock stops the server.
  """
  @spec checkout(GenServer.server(), key(), Servers.t(), pid() | nil) ::
          {:ok, pid()} | {:error, term()}
  def checkout(pool, key, definition, owner) do
    call(pool, {:checkout, key, definition, owner})
  end

  @doc "The tools every ready server for `workspace_root` advertises, in server order."
  @spec tools(GenServer.server(), String.t() | nil) :: [{String.t(), [Server.tool()]}]
  def tools(pool, workspace_root) do
    case call(pool, {:tools, workspace_root}) do
      {:error, _reason} -> []
      tools -> tools
    end
  end

  @doc """
  Whether any live server on this node advertises the model-facing name `mcp__s__t`.

  Deliberately not workspace-scoped: `Ouroboros.Provider.Native.Tools.lookup/3` is given
  a tool name and nothing else, and answering "no such tool" for a name some session on
  this node really does have would be a lie. The workspace-exact resolution happens in
  `Ouroboros.Provider.Native.Tools.Mcp`, which has the session's scope.
  """
  @spec advertised?(GenServer.server(), String.t()) :: boolean()
  def advertised?(pool, name) do
    call(pool, {:advertised, name}) == true
  end

  @doc "Describes every server this node owns: state, tools, restarts, uptime."
  @spec status(GenServer.server()) :: %{node: node(), servers: [map()]}
  def status(pool \\ __MODULE__) do
    case call(pool, :status) do
      {:error, reason} -> %{node: node(), servers: [], error: reason}
      status -> status
    end
  end

  @doc "Stops every server held for `workspace_root`. Used by tests and by teardown."
  @spec stop_workspace(GenServer.server(), String.t() | nil) :: :ok
  def stop_workspace(pool, workspace_root) do
    _ = call(pool, {:stop_workspace, workspace_root})
    :ok
  end

  @impl true
  def init(opts) do
    state = %{
      supervisor: Keyword.fetch!(opts, :server_supervisor),
      settings: Keyword.take(opts, Keyword.keys(Config.all())),
      servers: %{},
      owners: %{}
    }

    schedule_sweep(state)
    {:ok, state}
  end

  @impl true
  def handle_call({:ensure, root, definitions}, _from, state) do
    {state, placements} =
      Enum.reduce(definitions, {state, []}, fn definition, {state, acc} ->
        key = {root, definition.name}

        case start_if_needed(state, key, definition) do
          {:ok, state, server} -> {state, [placement(server) | acc]}
          {:error, state, reason} -> {state, [refused(key, definition, reason) | acc]}
        end
      end)

    {:reply, Enum.reverse(placements), state}
  end

  def handle_call({:checkout, key, definition, owner}, _from, state) do
    case start_if_needed(state, key, definition) do
      {:ok, state, %{state: :broken} = _server} ->
        {:reply, {:error, :broken}, state}

      {:ok, state, server} ->
        state = state |> claim(key, owner) |> touch(key)
        {:reply, {:ok, server.pid}, state}

      {:error, state, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:tools, root}, _from, state) do
    tools =
      state.servers
      |> Map.values()
      |> Enum.filter(&(elem(&1.key, 0) == root and &1.state == :ready))
      |> Enum.sort_by(& &1.name)
      |> Enum.map(&{&1.name, &1.tools})

    {:reply, tools, state}
  end

  def handle_call({:advertised, name}, _from, state) do
    advertised? =
      Enum.any?(state.servers, fn {_key, server} ->
        server.state == :ready and
          Enum.any?(server.tools, &(model_name(server.name, &1.name) == name))
      end)

    {:reply, advertised?, state}
  end

  def handle_call(:status, _from, state) do
    now = now_ms()

    servers =
      state.servers
      |> Map.values()
      |> Enum.sort_by(&{elem(&1.key, 0) || "", &1.name})
      |> Enum.map(&describe(&1, now))

    {:reply, %{node: node(), servers: servers}, state}
  end

  def handle_call({:stop_workspace, root}, _from, state) do
    state =
      state.servers
      |> Map.values()
      |> Enum.filter(&(elem(&1.key, 0) == root))
      |> Enum.reduce(state, fn server, state -> stop_server(state, server.key) end)

    {:reply, :ok, state}
  end

  @impl true
  def handle_info({:mcp_ready, key, pid, tools}, state) do
    case Map.fetch(state.servers, key) do
      {:ok, %{pid: ^pid} = server} ->
        server = %{server | state: :ready, tools: tools, ready_at: server.ready_at || now_ms()}
        {:noreply, put_server(state, server)}

      _stale ->
        {:noreply, state}
    end
  end

  def handle_info({:DOWN, ref, :process, pid, reason}, state) do
    cond do
      server = Enum.find_value(state.servers, &matching_server(&1, ref)) ->
        {:noreply, server_down(state, server, reason)}

      Map.has_key?(state.owners, pid) ->
        {:noreply, owner_down(state, pid)}

      true ->
        {:noreply, state}
    end
  end

  def handle_info({:restart, key}, state) do
    case Map.fetch(state.servers, key) do
      {:ok, %{state: :restarting} = server} -> {:noreply, spawn_server(state, server)}
      _gone -> {:noreply, state}
    end
  end

  def handle_info(:sweep, state) do
    schedule_sweep(state)
    {:noreply, sweep(state)}
  end

  def handle_info(_message, state), do: {:noreply, state}

  ## Lifecycle

  defp start_if_needed(state, key, definition) do
    case Map.fetch(state.servers, key) do
      {:ok, %{state: :broken} = server} ->
        if now_ms() >= server.broken_until,
          do: fresh(state, key, definition),
          else: {:ok, state, server}

      {:ok, server} ->
        {:ok, touch(state, key), server}

      :error ->
        fresh(state, key, definition)
    end
  end

  defp fresh(state, key, definition) do
    live = Enum.count(state.servers, fn {_key, server} -> server.state != :broken end)

    if live >= setting(state, :max_servers) do
      {:error, state, :too_many_servers}
    else
      now = now_ms()

      server = %{
        key: key,
        name: definition.name,
        definition: definition,
        root: elem(key, 0),
        pid: nil,
        ref: nil,
        state: :restarting,
        tools: [],
        restarts: 0,
        broken_until: nil,
        broken_reason: nil,
        started_at: now,
        ready_at: nil,
        last_used_at: now,
        owners: MapSet.new()
      }

      state = spawn_server(put_server(state, server), server)

      case Map.fetch(state.servers, key) do
        {:ok, spawned} -> {:ok, state, spawned}
        :error -> {:error, state, :spawn_failed}
      end
    end
  end

  defp spawn_server(state, server) do
    child = temporary_child(Server, server_opts(state, server))

    case DynamicSupervisor.start_child(state.supervisor, child) do
      {:ok, pid} ->
        ref = Process.monitor(pid)

        put_server(state, %{
          server
          | pid: pid,
            ref: ref,
            state: :starting,
            started_at: now_ms(),
            last_used_at: now_ms()
        })

      {:error, reason} ->
        mark_broken(state, server, {:spawn_failed, reason})
    end
  end

  defp server_opts(state, server) do
    Keyword.merge(
      [
        owner: self(),
        key: server.key,
        definition: server.definition,
        cwd: server.definition.cwd || server.root
      ],
      state.settings
    )
  end

  # `:temporary`: this pool decides when a server comes back, with a restart count and a
  # backoff the supervisor has no way to know about. A supervisor restart would respawn
  # a server that has already failed three times, immediately, forever.
  #
  # Deliberately not named `child_spec/1`: a private function of that name silently
  # overrides the public one `use GenServer` generates, and this module is itself a
  # supervised child.
  defp temporary_child(module, opts),
    do: %{id: make_ref(), start: {module, :start_link, [opts]}, restart: :temporary}

  defp server_down(state, server, reason) do
    restarts = server.restarts + 1

    if restarts > setting(state, :max_restarts) do
      mark_broken(state, %{server | restarts: restarts}, {:restart_limit, reason})
    else
      backoff = setting(state, :restart_backoff_ms) * Integer.pow(2, restarts - 1)
      Process.send_after(self(), {:restart, server.key}, backoff)

      put_server(state, %{server | pid: nil, ref: nil, state: :restarting, restarts: restarts})
    end
  end

  defp mark_broken(state, server, reason) do
    Logger.warning(fn ->
      "mcp marked #{server.name} for #{server.root || "(no workspace)"} broken: " <>
        inspect(reason, limit: 10)
    end)

    put_server(state, %{
      server
      | pid: nil,
        ref: nil,
        state: :broken,
        tools: [],
        broken_until: now_ms() + setting(state, :broken_ms),
        broken_reason: reason
    })
  end

  # The record goes now, not when the child finally exits. This table is the answer to
  # "what may be handed out", and a server being torn down may not be — so leaving it
  # here for the length of a shutdown grace would make `mcp.list` claim a server that
  # cannot serve, and would make the next `ensure` decline to spawn its replacement.
  # The child winds itself down on its own afterwards, bounded, and its `:DOWN` finds
  # no record and is ignored.
  defp stop_server(state, key) do
    case Map.pop(state.servers, key) do
      {nil, _servers} ->
        state

      {server, servers} ->
        if is_reference(server.ref), do: Process.demonitor(server.ref, [:flush])
        if is_pid(server.pid), do: Server.stop(server.pid)
        %{state | servers: servers}
    end
  end

  ## Claims

  defp claim(state, _key, nil), do: state

  defp claim(state, key, owner) when is_pid(owner) do
    owners =
      Map.update(state.owners, owner, %{ref: Process.monitor(owner), keys: MapSet.new([key])}, fn
        entry -> %{entry | keys: MapSet.put(entry.keys, key)}
      end)

    case Map.fetch(state.servers, key) do
      {:ok, server} ->
        %{state | owners: owners}
        |> put_server(%{server | owners: MapSet.put(server.owners, owner)})

      :error ->
        %{state | owners: owners}
    end
  end

  # The clean kill on session end. A key whose last claimant is gone has nothing left
  # that could want it, so it stops now rather than at the next idle sweep — an MCP
  # server is often somebody's API client, and leaving one running for ten minutes after
  # its session ended is a bill and a connection nobody asked for.
  defp owner_down(state, owner) do
    {entry, owners} = Map.pop(state.owners, owner)
    state = %{state | owners: owners}

    Enum.reduce(entry.keys, state, fn key, state ->
      case Map.fetch(state.servers, key) do
        {:ok, server} ->
          remaining = MapSet.delete(server.owners, owner)
          state = put_server(state, %{server | owners: remaining})
          if MapSet.size(remaining) == 0, do: stop_server(state, key), else: state

        :error ->
          state
      end
    end)
  end

  ## Sweep

  defp sweep(state) do
    now = now_ms()
    idle_ms = setting(state, :idle_ms)

    state.servers
    |> Map.values()
    |> Enum.reduce(state, fn server, state ->
      cond do
        server.state == :broken and now >= server.broken_until ->
          %{state | servers: Map.delete(state.servers, server.key)}

        server.state in [:starting, :ready] and MapSet.size(server.owners) == 0 and
            now - server.last_used_at >= idle_ms ->
          stop_server(state, server.key)

        true ->
          state
      end
    end)
  end

  # The sweep has to be able to notice an idle window shorter than its own period, or a
  # short `idle_ms` would be silently rounded up to the sweep interval.
  defp schedule_sweep(state) do
    period = max(250, min(setting(state, :sweep_ms), div(setting(state, :idle_ms), 4)))
    Process.send_after(self(), :sweep, period)
  end

  ## Projection

  defp describe(server, now) do
    %{
      name: server.name,
      workspace: server.root,
      state: server.state,
      scope: server.definition.scope,
      source: server.definition.source,
      command: server.definition.command,
      args: server.definition.args,
      cwd: server.definition.cwd,
      transport: :stdio,
      # Values, never. The count is an operator's question; the values are nobody's.
      env_count: map_size(server.definition.env),
      tools: length(server.tools),
      tool_names: Enum.map(server.tools, &model_name(server.name, &1.name)),
      restarts: server.restarts,
      claims: MapSet.size(server.owners),
      uptime_ms: now - server.started_at,
      idle_ms: now - server.last_used_at,
      broken_reason: server.broken_reason && inspect(server.broken_reason, limit: 10),
      broken_until_ms: server.broken_until && max(server.broken_until - now, 0)
    }
  end

  defp placement(server),
    do: %{name: server.name, key: server.key, state: server.state, pid: server.pid}

  defp refused(key, definition, reason),
    do: %{name: definition.name, key: key, state: :broken, pid: nil, reason: reason}

  ## Helpers

  defp model_name(server, tool), do: "mcp__" <> server <> "__" <> tool

  defp put_server(state, server),
    do: %{state | servers: Map.put(state.servers, server.key, server)}

  defp touch(state, key) do
    case Map.fetch(state.servers, key) do
      {:ok, server} -> put_server(state, %{server | last_used_at: now_ms()})
      :error -> state
    end
  end

  defp matching_server({_key, %{ref: ref} = server}, ref) when is_reference(ref), do: server
  defp matching_server(_entry, _ref), do: nil

  defp setting(state, key), do: Keyword.get(state.settings, key) || Config.get(key)

  defp now_ms, do: System.monotonic_time(:millisecond)

  defp call(pool, message) do
    GenServer.call(pool, message, @call_timeout)
  catch
    :exit, reason -> {:error, {:pool_unavailable, reason}}
  end
end
