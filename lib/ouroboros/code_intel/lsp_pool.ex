defmodule Ouroboros.CodeIntel.LspPool do
  @moduledoc """
  Owns every language server on this node, keyed by `{workspace_root, server_id}`.

  A language server belongs to the runtime, never to a session (AGENT_EXPERIENCE D7).
  Sessions acquire a ref-counted handle; the pool monitors the owner, so a session that
  crashes releases its claim without anyone noticing. Servers are spawned lazily on the
  first acquire, shared by every subsequent one for the same key, and stopped once no
  owner has held them for `idle_ms`.

  Failure is a state, not an exception. A server that dies is restarted with backoff up
  to `max_restarts`; past that the key is marked `:broken` for `broken_ms` and every call
  against it answers `{:error, :broken}` immediately, so a failing server is not
  respawned on every edit. Nothing here ever raises into a caller and nothing here
  blocks: requests are issued by the caller's own process against a pid this pool hands
  out, so one slow server cannot stall the pool's mailbox.

  Memory is governed twice, because the documented failure modes are 30 GB Serena
  processes and rust-analyzer on large repos (R4 §5, §"Pitfalls"). Each server has a soft
  limit: exceeding it restarts the server once, and a second breach marks the key broken.
  The host has a budget: while the measured total is at or above it, the pool refuses to
  spawn anything new — it never kills a healthy server to make room, because the caller
  that would lose its server did nothing wrong. RSS is read off-process on a timer; a
  reading that cannot be taken is `:unknown`, and unknown is never treated as a breach.

  The pool checkpoints nothing. It is ephemeral by design: on restart every server is
  gone, every document is closed, and the next acquire spawns fresh. There is no durable
  state worth keeping, because the only truth is the files on disk.
  """

  use GenServer

  require Logger

  alias Ouroboros.CodeIntel.Config
  alias Ouroboros.CodeIntel.Handle
  alias Ouroboros.CodeIntel.Lsp.Server

  @call_timeout 5_000

  @typedoc "Everything needed to spawn one server. Produced by `Ouroboros.CodeIntel.Registry`."
  @type spec :: %{
          required(:root) => String.t(),
          required(:server_id) => String.t(),
          required(:executable) => String.t(),
          optional(:args) => [String.t()],
          optional(:env) => [{String.t(), String.t()}],
          optional(:initialization_options) => map() | nil
        }

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc """
  Claims a server for the calling process, spawning it if this is the first claim.

  The claim is released when `release/2` is called or when the owner dies, whichever
  happens first.
  """
  @spec acquire(GenServer.server(), spec(), keyword()) :: {:ok, Handle.t()} | {:error, term()}
  def acquire(pool, spec, opts \\ []) do
    case Keyword.get(opts, :owner, self()) do
      owner when is_pid(owner) -> call(pool, {:acquire, spec, owner})
      other -> {:error, {:invalid_owner, other}}
    end
  end

  @spec release(GenServer.server(), Handle.t()) :: :ok
  def release(pool, %Handle{} = handle) do
    case call(pool, {:release, handle}) do
      :ok -> :ok
      {:error, _reason} -> :ok
    end
  end

  @doc """
  Returns a live server pid for `spec`, spawning it if needed and waiting for the
  handshake for at most `wait_ready_ms`.

  This is what a one-shot request uses: no claim is taken, but the server's idle clock is
  reset. The wait happens in the caller, never in the pool.
  """
  @spec checkout(GenServer.server(), spec(), keyword()) :: {:ok, pid()} | {:error, term()}
  def checkout(pool, spec, opts \\ []) do
    with {:ok, %{pid: pid, ready?: ready?}} <- call(pool, {:checkout, spec}) do
      if ready? do
        {:ok, pid}
      else
        wait_ms = Keyword.get(opts, :wait_ready_ms, Config.get(:initialize_timeout_ms))

        case Server.await_ready(pid, wait_ms) do
          :ok -> {:ok, pid}
          {:error, reason} -> {:error, reason}
        end
      end
    end
  end

  @doc """
  Describes every server this node owns: state, pids, RSS, root, uptime, restarts, and
  the documents held open.
  """
  @spec status(GenServer.server()) :: %{
          node: node(),
          budget_bytes: non_neg_integer(),
          used_bytes: non_neg_integer(),
          servers: [map()]
        }
  def status(pool \\ __MODULE__) do
    case call(pool, :status) do
      {:error, reason} ->
        %{node: node(), budget_bytes: 0, used_bytes: 0, servers: [], error: reason}

      status ->
        status
    end
  end

  @doc false
  @spec stop_server(GenServer.server(), {String.t(), String.t()}) :: :ok | {:error, term()}
  def stop_server(pool, key), do: call(pool, {:stop_server, key})

  @doc false
  @spec sweep(GenServer.server()) :: :ok | {:error, term()}
  def sweep(pool), do: call(pool, :sweep_now)

  @doc false
  @spec measure(GenServer.server()) :: :ok | {:error, term()}
  def measure(pool), do: call(pool, :measure_now, 15_000)

  # Every entry point is a bounded call that answers an error tuple. A dead or wedged
  # pool must look like a language server that is unavailable, not like a crash in the
  # caller.
  defp call(pool, message, timeout \\ @call_timeout) do
    GenServer.call(pool, message, timeout)
  catch
    :exit, reason -> {:error, {:pool_unavailable, reason}}
  end

  ## Server

  @impl true
  def init(opts) do
    state = %{
      server_supervisor: Keyword.fetch!(opts, :server_supervisor),
      opts: opts,
      servers: %{},
      owners: %{},
      monitors: %{},
      measuring: nil
    }

    schedule(:sweep, sweep_period(state))
    schedule(:measure, setting(state, :memory_poll_ms))
    {:ok, state}
  end

  @impl true
  def handle_call({:acquire, spec, owner}, _from, state) do
    case ensure_server(state, spec) do
      {:ok, state, server} ->
        ref = Process.monitor(owner)

        handle = %Handle{
          ref: ref,
          id: Handle.id(node(), server.root, server.server_id),
          node: node(),
          root: server.root,
          server_id: server.server_id,
          owner: owner
        }

        server = %{server | owners: Map.put(server.owners, ref, owner)}

        state = %{
          state
          | servers: Map.put(state.servers, server.key, server),
            owners: Map.put(state.owners, ref, server.key)
        }

        {:reply, {:ok, handle}, state}

      {:error, reason, state} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:release, %Handle{ref: ref}}, _from, state) do
    {:reply, :ok, drop_owner(state, ref)}
  end

  def handle_call({:checkout, spec}, _from, state) do
    case ensure_server(state, spec) do
      {:ok, state, %{pid: pid} = server} when is_pid(pid) ->
        {:reply, {:ok, %{pid: pid, ready?: server.state == :ready}}, state}

      {:ok, state, server} ->
        {:reply, {:error, server.state}, state}

      {:error, reason, state} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call(:status, _from, state) do
    now = now_ms()

    servers =
      state.servers
      |> Map.values()
      |> Enum.sort_by(& &1.started_at)
      |> Enum.map(&describe(&1, now))

    {:reply,
     %{
       node: node(),
       budget_bytes: setting(state, :memory_budget_bytes),
       used_bytes: used_bytes(state),
       servers: servers
     }, state}
  end

  def handle_call({:stop_server, key}, _from, state) do
    case Map.fetch(state.servers, key) do
      {:ok, server} -> {:reply, :ok, begin_stop(state, server)}
      :error -> {:reply, {:error, :not_found}, state}
    end
  end

  def handle_call(:sweep_now, _from, state), do: {:reply, :ok, run_sweep(state)}

  def handle_call(:measure_now, _from, state) do
    {:reply, :ok, apply_measurements(state, measurements(state))}
  end

  @impl true
  def handle_info({:code_intel_lsp, key, message}, state),
    do: {:noreply, from_server(state, key, message)}

  def handle_info(:sweep, state) do
    state = run_sweep(state)
    schedule(:sweep, sweep_period(state))
    {:noreply, state}
  end

  def handle_info(:measure, state) do
    state = start_measurement(state)
    schedule(:measure, setting(state, :memory_poll_ms))
    {:noreply, state}
  end

  def handle_info({:measured, readings}, state) when is_map(readings) do
    {:noreply, apply_measurements(state, readings)}
  end

  def handle_info({:restart, key}, state) do
    case Map.fetch(state.servers, key) do
      {:ok, %{state: :restarting} = server} -> {:noreply, spawn_server(state, server)}
      _other -> {:noreply, state}
    end
  end

  def handle_info({:DOWN, ref, :process, _pid, reason}, state) do
    cond do
      Map.has_key?(state.monitors, ref) -> {:noreply, server_down(state, ref, reason)}
      Map.has_key?(state.owners, ref) -> {:noreply, drop_owner(state, ref)}
      state.measuring == ref -> {:noreply, %{state | measuring: nil}}
      true -> {:noreply, state}
    end
  end

  def handle_info(_message, state), do: {:noreply, state}

  ## Server lifecycle

  defp ensure_server(state, spec) do
    with {:ok, key} <- key_for(spec) do
      case Map.fetch(state.servers, key) do
        {:ok, %{state: :broken} = server} ->
          if now_ms() >= server.broken_until do
            state = %{state | servers: Map.delete(state.servers, key)}
            ensure_server(state, spec)
          else
            {:error, :broken, state}
          end

        {:ok, server} ->
          server = %{server | last_used_at: now_ms()}
          {:ok, %{state | servers: Map.put(state.servers, key, server)}, server}

        :error ->
          start_new(state, key, spec)
      end
    else
      {:error, reason} -> {:error, reason, state}
    end
  end

  defp start_new(state, key, spec) do
    budget = setting(state, :memory_budget_bytes)
    used = used_bytes(state)

    if used >= budget do
      {:error, {:memory_budget_exhausted, used, budget}, state}
    else
      now = now_ms()

      server = %{
        key: key,
        root: elem(key, 0),
        server_id: elem(key, 1),
        spec: spec,
        pid: nil,
        monitor: nil,
        state: :restarting,
        os_pid: nil,
        rss_bytes: nil,
        server_info: nil,
        started_at: now,
        last_used_at: now,
        restarts: 0,
        memory_restarts: 0,
        broken_until: nil,
        broken_reason: nil,
        restart_after_stop: false,
        owners: %{},
        documents: %{}
      }

      state = spawn_server(state, server)

      case Map.fetch(state.servers, key) do
        {:ok, %{state: :broken}} -> {:error, :broken, state}
        {:ok, started} -> {:ok, state, started}
        :error -> {:error, :spawn_failed, state}
      end
    end
  end

  defp spawn_server(state, server) do
    spec = server.spec

    child = %{
      id: {Server, server.key},
      start:
        {Server, :start_link,
         [
           [
             owner: self(),
             key: server.key,
             root: server.root,
             server_id: server.server_id,
             executable: Map.fetch!(spec, :executable),
             args: Map.get(spec, :args, []),
             env: Map.get(spec, :env, []),
             initialization_options: Map.get(spec, :initialization_options),
             initialize_timeout_ms: setting(state, :initialize_timeout_ms),
             shutdown_grace_ms: setting(state, :shutdown_grace_ms),
             max_frame_bytes: setting(state, :max_frame_bytes),
             max_pending_requests: setting(state, :max_pending_requests)
           ]
         ]},
      restart: :temporary,
      shutdown: 5_000,
      type: :worker
    }

    case DynamicSupervisor.start_child(state.server_supervisor, child) do
      {:ok, pid} ->
        monitor = Process.monitor(pid)

        server = %{
          server
          | pid: pid,
            monitor: monitor,
            state: :starting,
            documents: %{},
            last_used_at: now_ms()
        }

        %{
          state
          | servers: Map.put(state.servers, server.key, server),
            monitors: Map.put(state.monitors, monitor, server.key)
        }

      {:error, reason} ->
        Logger.warning(fn ->
          "code_intel could not start #{server.server_id} for #{server.root}: #{inspect(reason)}"
        end)

        mark_broken(state, server, {:spawn_failed, reason})
    end
  end

  defp server_down(state, ref, reason) do
    {key, monitors} = Map.pop(state.monitors, ref)
    state = %{state | monitors: monitors}

    case Map.fetch(state.servers, key) do
      :error ->
        state

      {:ok, %{state: :broken}} ->
        state

      {:ok, %{state: :stopping, restart_after_stop: true} = server} ->
        spawn_server(state, %{server | restart_after_stop: false})

      {:ok, %{state: :stopping} = server} ->
        release_owners(state, server)

      {:ok, server} ->
        restarts = server.restarts + 1
        max_restarts = setting(state, :max_restarts)

        if restarts > max_restarts do
          mark_broken(state, %{server | restarts: restarts}, {:restart_limit, reason})
        else
          backoff = setting(state, :restart_backoff_ms) * Integer.pow(2, restarts - 1)
          Process.send_after(self(), {:restart, key}, backoff)

          server = %{
            server
            | pid: nil,
              monitor: nil,
              os_pid: nil,
              rss_bytes: nil,
              state: :restarting,
              restarts: restarts,
              documents: %{}
          }

          %{state | servers: Map.put(state.servers, key, server)}
        end
    end
  end

  defp mark_broken(state, server, reason) do
    Logger.warning(fn ->
      "code_intel marked #{server.server_id} for #{server.root} broken: #{inspect(reason)}"
    end)

    monitors =
      case server.monitor do
        ref when is_reference(ref) ->
          Process.demonitor(ref, [:flush])
          Map.delete(state.monitors, ref)

        _absent ->
          state.monitors
      end

    state = %{state | monitors: monitors}

    server = %{
      server
      | pid: nil,
        monitor: nil,
        os_pid: nil,
        rss_bytes: nil,
        state: :broken,
        broken_until: now_ms() + setting(state, :broken_ms),
        broken_reason: reason,
        documents: %{}
    }

    %{state | servers: Map.put(state.servers, server.key, server)}
  end

  defp begin_stop(state, %{pid: pid} = server) when is_pid(pid) do
    Server.stop(pid)
    %{state | servers: Map.put(state.servers, server.key, %{server | state: :stopping})}
  end

  defp begin_stop(state, server), do: release_owners(state, server)

  defp release_owners(state, server) do
    owners = Map.drop(state.owners, Map.keys(server.owners))
    Enum.each(Map.keys(server.owners), &Process.demonitor(&1, [:flush]))

    %{state | servers: Map.delete(state.servers, server.key), owners: owners}
  end

  defp drop_owner(state, ref) do
    case Map.pop(state.owners, ref) do
      {nil, _owners} ->
        state

      {key, owners} ->
        Process.demonitor(ref, [:flush])
        state = %{state | owners: owners}

        case Map.fetch(state.servers, key) do
          :error ->
            state

          {:ok, server} ->
            server = %{server | owners: Map.delete(server.owners, ref), last_used_at: now_ms()}
            %{state | servers: Map.put(state.servers, key, server)}
        end
    end
  end

  ## Messages from a server process

  defp from_server(state, key, {:started, pid, os_pid}) do
    update_server(state, key, fn
      %{pid: ^pid} = server -> %{server | os_pid: os_pid}
      server -> server
    end)
  end

  defp from_server(state, key, {:ready, server_info}) do
    update_server(state, key, fn server ->
      %{server | state: :ready, server_info: server_info}
    end)
  end

  defp from_server(state, _key, _message), do: state

  defp update_server(state, key, fun) do
    case Map.fetch(state.servers, key) do
      {:ok, server} -> %{state | servers: Map.put(state.servers, key, fun.(server))}
      :error -> state
    end
  end

  ## Sweeps

  defp run_sweep(state) do
    now = now_ms()
    idle_ms = setting(state, :idle_ms)

    state.servers
    |> Map.values()
    |> Enum.reduce(state, fn server, acc ->
      cond do
        server.state == :broken and now >= server.broken_until ->
          %{acc | servers: Map.delete(acc.servers, server.key)}

        server.state in [:starting, :ready] and map_size(server.owners) == 0 and
            now - server.last_used_at >= idle_ms ->
          begin_stop(acc, server)

        true ->
          acc
      end
    end)
  end

  # The sweep has to be able to notice an idle window shorter than its own period, or a
  # short `idle_ms` would be silently rounded up to the sweep interval.
  defp sweep_period(state) do
    max(250, min(setting(state, :sweep_ms), div(setting(state, :idle_ms), 4)))
  end

  ## Memory

  defp start_measurement(%{measuring: ref} = state) when is_reference(ref), do: state

  defp start_measurement(state) do
    targets =
      for {key, %{os_pid: os_pid}} <- state.servers, is_integer(os_pid), do: {key, os_pid}

    if targets == [] do
      state
    else
      pool = self()
      reader = rss_reader(state)

      {_pid, ref} =
        spawn_monitor(fn ->
          readings =
            Map.new(targets, fn {key, os_pid} ->
              {key,
               case reader.(os_pid) do
                 {:ok, bytes} -> bytes
                 _unknown -> :unknown
               end}
            end)

          send(pool, {:measured, readings})
        end)

      %{state | measuring: ref}
    end
  end

  defp measurements(state) do
    reader = rss_reader(state)

    for {key, %{os_pid: os_pid}} <- state.servers, is_integer(os_pid), into: %{} do
      {key,
       case reader.(os_pid) do
         {:ok, bytes} -> bytes
         _unknown -> :unknown
       end}
    end
  end

  defp apply_measurements(state, readings) do
    limit = setting(state, :server_memory_limit_bytes)

    Enum.reduce(readings, state, fn {key, reading}, acc ->
      case Map.fetch(acc.servers, key) do
        :error ->
          acc

        {:ok, server} ->
          server = %{
            server
            | rss_bytes: if(is_integer(reading), do: reading, else: server.rss_bytes)
          }

          acc = %{acc | servers: Map.put(acc.servers, key, server)}

          if is_integer(reading) and reading > limit and server.state in [:starting, :ready] do
            over_limit(acc, server, reading, limit)
          else
            acc
          end
      end
    end)
  end

  # A server over its own soft limit gets exactly one restart. Restarting it twice would
  # be a loop, because whatever made it grow is still in the workspace.
  defp over_limit(state, server, bytes, limit) do
    Logger.warning(fn ->
      "code_intel: #{server.server_id} for #{server.root} holds #{bytes} bytes, over #{limit}"
    end)

    if is_pid(server.pid), do: Server.stop(server.pid)

    if server.memory_restarts >= 1 do
      mark_broken(state, server, :memory_limit)
    else
      # The respawn waits for this server's DOWN rather than racing it, so one key never
      # holds two OS processes at once.
      server = %{
        server
        | state: :stopping,
          restart_after_stop: true,
          memory_restarts: server.memory_restarts + 1
      }

      %{state | servers: Map.put(state.servers, server.key, server)}
    end
  end

  defp used_bytes(state) do
    state.servers
    |> Map.values()
    |> Enum.reduce(0, fn
      %{rss_bytes: bytes}, total when is_integer(bytes) -> total + bytes
      _server, total -> total
    end)
  end

  defp rss_reader(state) do
    case setting(state, :rss_reader) do
      fun when is_function(fun, 1) -> fun
      {module, function, args} -> &apply(module, function, [&1 | args])
    end
  end

  ## Shared

  defp key_for(%{root: root, server_id: server_id})
       when is_binary(root) and is_binary(server_id) and root != "" and server_id != "",
       do: {:ok, {root, server_id}}

  defp key_for(spec), do: {:error, {:invalid_server_spec, spec}}

  defp describe(server, now) do
    %{
      id: Handle.id(node(), server.root, server.server_id),
      node: node(),
      root: server.root,
      server_id: server.server_id,
      state: server.state,
      pid: server.pid && inspect(server.pid),
      os_pid: server.os_pid,
      rss_bytes: server.rss_bytes,
      uptime_ms: now - server.started_at,
      idle_ms: now - server.last_used_at,
      restarts: server.restarts,
      memory_restarts: server.memory_restarts,
      owners: map_size(server.owners),
      broken_until_ms: server.broken_until && max(server.broken_until - now, 0),
      server_info: server.server_info,
      documents: server.documents |> Map.keys() |> Enum.sort()
    }
  end

  defp schedule(message, period), do: Process.send_after(self(), message, period)

  defp setting(state, key) do
    case Keyword.fetch(state.opts, key) do
      {:ok, value} -> value
      :error -> Config.get(key)
    end
  end

  defp now_ms, do: System.monotonic_time(:millisecond)
end
