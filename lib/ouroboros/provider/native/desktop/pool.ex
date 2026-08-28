defmodule Ouroboros.Provider.Native.Desktop.Pool do
  @moduledoc """
  Owns the one Computer Use helper process this node runs, and the per-session last state.

  There is exactly one helper on a node (D11): a screenshot stream and a TCC grant are
  expensive and per-binary, not per-session, so a second helper pid would buy nothing and
  prompt for permission again. This GenServer is that single owner. It spawns the resolved
  helper binary with the `serve` subcommand, speaks the newline-delimited JSON-RPC of
  `Ouroboros.Provider.Native.Desktop.Codec` over its stdio, keeps at most one request in
  flight, and hands every request a hard deadline.

  ## Broken is a state, not a crash

  A helper that never answers its handshake, dies, floods stdout with noise, or oversizes a
  frame is marked **broken** for a cooldown window and every call against it answers at once
  rather than waiting — the same posture `Ouroboros.Provider.Native.Mcp.Pool` takes, so a
  helper that fails on every spawn is not respawned on every turn. A call after the window
  reconnects; the call that trips the reconnect is told so and the next one is served. The
  pool process itself does not crash when its child does: it holds the per-session snapshot
  map, and a crash there would drop state a live session still needs.

  ## The last state lives here, in the BEAM

  `remember_state/3` keeps `%{session_dir => last_state}` (D11, invariant #5). The helper is
  stateless: it re-finds a window from the target it is handed, so a helper crash "drops
  nothing durable; the next state rebuilds". The map is keyed by the session's directory —
  the one per-session handle a tool's context carries — and is bounded so a long-lived node
  cannot grow it without limit; `forget_state/2` drops one when a session ends.

  ## Env is filtered

  The helper is spawned with the node's environment minus anything that reads like a
  secret — the gateway token, provider API keys, OAuth material (§7). The helper owns pixels
  and input; it has no business holding this runtime's credentials, and a child that cannot
  read them cannot leak them.
  """

  use GenServer

  require Logger

  alias Ouroboros.Provider.Native.Desktop
  alias Ouroboros.Provider.Native.Desktop.Codec

  # Names of environment variables the helper is never given. It owns host I/O, not
  # credentials; stripping generously is safe because it needs none of these to run.
  @secret_env ~r/(API_?KEY|_TOKEN|SECRET|OAUTH|PASSWORD|CREDENTIAL|GATEWAY_TOKEN)/i

  # How long a broken helper is left alone before a call is allowed to reconnect it. Long
  # enough that a helper failing on every spawn is not respawned on every turn, short enough
  # that a transient failure clears within a working session.
  @broken_ms 15_000

  # Lines of non-JSON stdout tolerated before the transport is treated as broken. A helper
  # that has started logging to stdout is misbehaving; a couple of banner lines are not.
  @max_noise 20

  # How many sessions' last states are retained. The map holds one small struct per session;
  # this only bounds a pathologically long-lived node, and eviction is oldest-first.
  @max_sessions 128

  # In-flight is one helper request. Further callers wait in this queue rather than failing
  # `:busy` the moment two sessions observe at once.
  @max_queue 4
  @typedoc "What `status/1` reports about the helper."
  @type status :: %{
          phase: :idle | :handshaking | :ready | :broken,
          helper_path: String.t(),
          os_pid: pos_integer() | nil,
          doctor: map() | nil,
          sessions: non_neg_integer(),
          broken_reason: term() | nil
        }

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc """
  Starts a detached pool. Tests use this so a child's exit does not travel through
  the test process. The node supervisor starts the named singleton via `start_link/1`.
  """
  @spec start(keyword()) :: GenServer.on_start()
  def start(opts) do
    GenServer.start(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc """
  Issues one request to the helper and waits at most `timeout_ms` for the answer.

  Never raises and never exits the caller. A dead helper, a full queue, and a helper
  that does not answer are error tuples. Overlapping callers wait in a bounded queue.
  """
  @spec request(GenServer.server(), String.t(), map(), pos_integer()) ::
          {:ok, term()} | {:error, term()}
  def request(server, method, params, timeout_ms) do
    GenServer.call(server, {:request, method, params, timeout_ms}, timeout_ms + 1_000)
  catch
    :exit, reason -> {:error, {:pool_unavailable, reason}}
  end

  @doc "The helper's readiness (§7.1), fresh from the helper."
  @spec doctor(GenServer.server(), pos_integer()) :: {:ok, map()} | {:error, term()}
  def doctor(server, timeout_ms), do: request(server, "doctor", %{}, timeout_ms)

  @doc "The helper's window list (§7.2)."
  @spec windows(GenServer.server(), pos_integer()) :: {:ok, map()} | {:error, term()}
  def windows(server, timeout_ms), do: request(server, "windows", %{}, timeout_ms)

  @doc "One `state` capture (§7.3). The staging of the returned image path is the caller's."
  @spec state(GenServer.server(), map(), pos_integer()) :: {:ok, map()} | {:error, term()}
  def state(server, params, timeout_ms) when is_map(params),
    do: request(server, "state", params, timeout_ms)

  @doc "The session dirs this pool has staged a snapshot for — the artifact search set (§8.5)."
  @spec session_dirs(GenServer.server()) :: [String.t()]
  def session_dirs(server), do: GenServer.call(server, :session_dirs)

  @doc "Records the last state for `session_dir` (D11)."
  @spec remember_state(GenServer.server(), String.t(), map()) :: :ok
  def remember_state(server, session_dir, state) when is_binary(session_dir) and is_map(state) do
    GenServer.cast(server, {:remember_state, session_dir, state})
  end

  @doc "The last state recorded for `session_dir`, or `nil`."
  @spec last_state(GenServer.server(), String.t()) :: map() | nil
  def last_state(server, session_dir) when is_binary(session_dir) do
    GenServer.call(server, {:last_state, session_dir})
  catch
    :exit, _reason -> nil
  end

  @doc "Drops the last state for `session_dir`. Called when a session ends."
  @spec forget_state(GenServer.server(), String.t()) :: :ok
  def forget_state(server, session_dir) when is_binary(session_dir) do
    GenServer.cast(server, {:forget_state, session_dir})
  end

  @doc """
  Tells the in-flight `act` owned by `caller` to abort between events.

  A notification: no answer is owed, and this never starts a helper that is not
  already running. A cancel for a queued or unrelated caller is a no-op, so
  interrupting session B cannot abort session A's inflight act.
  """
  @spec cancel(pid()) :: :ok
  def cancel(caller) when is_pid(caller), do: cancel(__MODULE__, caller)

  @spec cancel(GenServer.server(), pid()) :: :ok
  def cancel(server, caller) when is_pid(caller) do
    GenServer.cast(server, {:cancel, caller})
  end

  @doc "Describes the helper this node owns: phase, os pid, last doctor, session count."
  @spec status(GenServer.server()) :: status()
  def status(server \\ __MODULE__) do
    GenServer.call(server, :status)
  catch
    :exit, reason -> %{phase: :broken, broken_reason: {:pool_unavailable, reason}, sessions: 0}
  end

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)

    state = %{
      helper_path: Keyword.get(opts, :helper_path) || Desktop.helper_path(),
      settings: settings(opts),
      port: nil,
      os_pid: nil,
      buffer: <<>>,
      noise: 0,
      next_id: 1,
      phase: :idle,
      inflight: nil,
      queue: :queue.new(),
      broken_until: 0,
      broken_reason: nil,
      doctor: nil,
      snapshots: %{},
      seq: 0
    }

    # An explicit `helper_path` is a test (or operator override) that wants the child now.
    # The supervised singleton stays idle until a request or probe needs it, so a node
    # with the flag off never prompts TCC at boot.
    if Keyword.has_key?(opts, :helper_path) do
      {:ok, connect(state)}
    else
      {:ok, state}
    end
  end

  @impl true
  def handle_call({:request, method, params, timeout}, from, state) do
    # Mint the monitor and absolute deadline at receipt, before reconnect or queue work.
    item = request_item(from, method, params, timeout)

    cond do
      state.phase == :ready and state.inflight == nil ->
        case issue_item(state, item) do
          {:ok, state} ->
            {:noreply, state}

          {:expired, state} ->
            cleanup_item(item)
            {:reply, {:error, :timeout}, state}

          {:error, reason} ->
            cleanup_item(item)
            {:reply, {:error, reason}, go_broken(state, {:transport_closed, reason})}
        end

      queueable?(state) ->
        state = maybe_connect(state)

        if state.phase == :broken do
          cleanup_item(item)
          {:reply, {:error, :broken}, state}
        else
          {:noreply, enqueue(state, item)}
        end

      state.phase == :broken ->
        cleanup_item(item)
        {:reply, {:error, :broken}, state}

      true ->
        cleanup_item(item)
        {:reply, {:error, :busy}, state}
    end
  end

  def handle_call({:last_state, session_dir}, _from, state) do
    reply =
      case Map.get(state.snapshots, session_dir) do
        {_seq, last} -> last
        _absent -> nil
      end

    {:reply, reply, state}
  end

  def handle_call(:status, _from, state) do
    {:reply,
     %{
       phase: state.phase,
       helper_path: state.helper_path,
       os_pid: state.os_pid,
       doctor: state.doctor,
       sessions: map_size(state.snapshots),
       broken_reason: state.broken_reason
     }, state}
  end

  def handle_call(:session_dirs, _from, state) do
    {:reply, Map.keys(state.snapshots), state}
  end

  @impl true
  def handle_cast({:remember_state, session_dir, last}, state) do
    {:noreply, put_snapshot(state, session_dir, last)}
  end

  def handle_cast({:forget_state, session_dir}, state) do
    {:noreply, %{state | snapshots: Map.delete(state.snapshots, session_dir)}}
  end

  def handle_cast({:cancel, caller}, state) when is_pid(caller) do
    case state.inflight do
      %{kind: {:caller, item}, method: "act"}
      when item.caller == caller and is_port(state.port) ->
        _ = write(state, Codec.notification("cancel", %{}))

      _other ->
        :ok
    end

    {:noreply, state}
  end

  @impl true
  def handle_info({port, {:data, data}}, %{port: port} = state) do
    case Codec.decode(state.buffer <> data, state.settings.max_frame_bytes) do
      {:ok, frames, noise, rest} ->
        state = %{state | buffer: rest, noise: state.noise + noise}

        if state.noise > @max_noise do
          {:noreply, go_broken(state, {:noise_limit, state.noise})}
        else
          {:noreply, Enum.reduce(frames, state, &handle_frame/2)}
        end

      {:error, reason} ->
        {:noreply, go_broken(state, {:protocol_error, reason})}
    end
  end

  # stderr is the helper's own log; it is neither buffered nor forwarded, so a token in the
  # helper's diagnostics cannot reach this node's logs.
  def handle_info({port, {:exit_status, status}}, %{port: port} = state) do
    {:noreply, go_broken(%{state | port: nil, os_pid: nil}, {:helper_exited, status})}
  end

  def handle_info({:deadline, id}, %{inflight: %{id: id, kind: :handshake}} = state) do
    {:noreply, go_broken(state, :handshake_timeout)}
  end

  def handle_info(
        {:request_deadline, request_ref},
        %{inflight: %{kind: {:caller, %{ref: request_ref} = item}}} = state
      ) do
    Process.demonitor(item.monitor, [:flush])
    GenServer.reply(item.from, {:error, :timeout})
    {:noreply, abandon_inflight(state, item)}
  end

  def handle_info({:request_deadline, request_ref}, state) do
    case remove_queued(state.queue, request_ref, :ref) do
      {nil, _queue} ->
        {:noreply, state}

      {item, queue} ->
        Process.demonitor(item.monitor, [:flush])
        GenServer.reply(item.from, {:error, :timeout})
        {:noreply, %{state | queue: queue}}
    end
  end

  def handle_info(
        {:DOWN, monitor, :process, _caller, _reason},
        %{inflight: %{kind: {:caller, %{monitor: monitor} = item}}} = state
      ) do
    drop_timer(item.deadline)
    {:noreply, abandon_inflight(state, item)}
  end

  def handle_info({:DOWN, monitor, :process, _caller, _reason}, state) do
    case remove_queued(state.queue, monitor, :monitor) do
      {nil, _queue} ->
        {:noreply, state}

      {item, queue} ->
        drop_timer(item.deadline)
        {:noreply, %{state | queue: queue}}
    end
  end

  def handle_info(
        {:abandon_deadline, id},
        %{inflight: %{id: id, kind: {:abandoned, _request_ref}}} = state
      ) do
    # The timed-out/callerless helper request did not acknowledge cancellation. Kill that
    # exact child before reconnecting so it cannot execute later beside a replacement.
    {:noreply, state |> Map.put(:inflight, nil) |> connect()}
  end

  def handle_info({:deadline, _stale_id}, state), do: {:noreply, state}
  def handle_info({:abandon_deadline, _stale_id}, state), do: {:noreply, state}

  # The port is linked to this process and, because we trap exits, its termination arrives
  # here as an `{:EXIT, port, _}` in addition to the `{:exit_status, _}` the exit-status
  # option delivers. The status message is the one that drove `go_broken`; this signal is
  # spent, and stopping on it would kill the pool every time its child does.
  def handle_info({:EXIT, port, _reason}, state) when is_port(port), do: {:noreply, state}

  # A non-port `{:EXIT, …}` is the linked starter going away (`start_link`, a test); follow
  # it down. The detached singleton (`start/1`) has no such link.
  def handle_info({:EXIT, _pid, reason}, state), do: {:stop, reason, state}

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    kill(state)
    :ok
  end

  ## Lifecycle

  # (Re)opens the child and starts the doctor handshake. Failure to spawn leaves the pool
  # broken rather than crashing it, so a node with the flag on but a missing or unrunnable
  # helper answers every call with an error instead of a supervision storm.
  defp connect(state) do
    state = hard_close(state)

    case open_port(%{state | buffer: <<>>, noise: 0, inflight: nil}) do
      {:ok, state} -> start_handshake(state)
      {:error, reason} -> go_broken(state, {:spawn_failed, reason})
    end
  end

  defp start_handshake(state) do
    case issue(state, "doctor", %{}, :handshake, state.settings.handshake_timeout_ms) do
      {:ok, state} -> %{state | phase: :handshaking}
      {:error, reason} -> go_broken(state, {:transport_closed, reason})
    end
  end

  defp handle_frame(%{"id" => id} = frame, %{inflight: %{id: id, kind: kind} = inflight} = state) do
    drop_timer(inflight.deadline)
    route(kind, answer(frame), %{state | inflight: nil})
  end

  # A frame with no matching in-flight id — a late response to a timed-out request, or a
  # helper-initiated message this phase does not serve — is ignored rather than acted on.
  defp handle_frame(_frame, state), do: state

  defp route(:handshake, {:ok, doctor}, state) do
    drain(%{state | phase: :ready, doctor: normalize_doctor(doctor)})
  end

  defp route(:handshake, {:error, reason}, state),
    do: go_broken(state, {:handshake_failed, reason})

  defp route({:caller, item}, reply, state) when is_map(item) do
    Process.demonitor(item.monitor, [:flush])
    GenServer.reply(item.from, reply)
    drain(state)
  end

  defp route({:abandoned, _request_ref}, _reply, state), do: drain(state)

  defp answer(%{"error" => %{} = error}),
    do: {:error, {:rpc_error, Map.get(error, "code"), Map.get(error, "message")}}

  defp answer(%{"result" => result}), do: {:ok, result}
  defp answer(_frame), do: {:error, {:malformed_result, "neither result nor error"}}

  defp issue(state, method, params, kind, timeout_ms) do
    {id, state} = take_id(state)

    case write(state, Codec.request(id, method, params)) do
      :ok ->
        ref = Process.send_after(self(), {:deadline, id}, timeout_ms)
        {:ok, %{state | inflight: %{id: id, kind: kind, method: method, deadline: ref}}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp issue_item(state, item) do
    if item.expires_at <= now() or not Process.alive?(item.caller) do
      {:expired, state}
    else
      {id, state} = take_id(state)

      case write(state, Codec.request(id, item.method, item.params)) do
        :ok ->
          {:ok,
           %{
             state
             | inflight: %{
                 id: id,
                 kind: {:caller, item},
                 method: item.method,
                 deadline: item.deadline
               }
           }}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  defp take_id(state), do: {state.next_id, %{state | next_id: state.next_id + 1}}

  # Mark broken and answer whoever was waiting. The pool keeps running: it owns the snapshot
  # map, which a live session still needs, and the next call after the cooldown reconnects.
  defp go_broken(state, reason) do
    if state.inflight do
      drop_timer(state.inflight.deadline)

      case state.inflight.kind do
        {:caller, item} when is_map(item) ->
          Process.demonitor(item.monitor, [:flush])
          GenServer.reply(item.from, {:error, :broken})

        {:abandoned, _request_ref} ->
          :ok

        :handshake ->
          :ok
      end
    end

    Enum.each(:queue.to_list(Map.get(state, :queue, :queue.new())), fn item ->
      cleanup_item(item)
      GenServer.reply(item.from, {:error, :broken})
    end)

    Logger.debug(fn -> "computer-use helper broken: #{inspect(reason, limit: 10)}" end)

    %{
      hard_close(state)
      | phase: :broken,
        inflight: nil,
        queue: :queue.new(),
        buffer: <<>>,
        broken_until: now() + @broken_ms,
        broken_reason: reason
    }
  end

  ## Transport

  defp open_port(state) do
    port =
      Port.open(
        {:spawn_executable, String.to_charlist(state.helper_path)},
        [
          :binary,
          :exit_status,
          :use_stdio,
          :hide,
          {:args, serve_args(state)},
          {:env, filtered_env()}
        ]
      )

    os_pid =
      case Port.info(port, :os_pid) do
        {:os_pid, pid} -> pid
        _absent -> nil
      end

    {:ok, %{state | port: port, os_pid: os_pid}}
  rescue
    error -> {:error, Exception.message(error)}
  end

  # The helper's own deny belt (§7.3, §12): even if this node's Elixir denylist were
  # incomplete, the helper refuses to observe or act on a bundle id it was launched to deny.
  # Repeated `--deny-app <id>` argv, charlists for the port.
  defp serve_args(_state) do
    [~c"serve"] ++
      Enum.flat_map(Desktop.denied_app_ids(), fn id ->
        [~c"--deny-app", String.to_charlist(id)]
      end)
  end

  # Erlang's `env` option modifies the inherited environment rather than replacing it, so
  # the helper keeps PATH, HOME, TMPDIR, and the windowserver session it needs for capture,
  # and only the secret-shaped variables are unset (value `false` removes one).
  defp filtered_env do
    System.get_env()
    |> Enum.filter(fn {name, _value} -> Regex.match?(@secret_env, name) end)
    |> Enum.map(fn {name, _value} -> {String.to_charlist(name), false} end)
  end

  defp write(%{port: nil}, _frames), do: {:error, :closed}

  defp write(state, frames) do
    Port.command(state.port, frames)
    :ok
  rescue
    ArgumentError -> {:error, :closed}
  end

  defp close_port(%{port: port} = state) when is_port(port) do
    try do
      Port.close(port)
    rescue
      ArgumentError -> :ok
    end

    %{state | port: nil}
  end

  defp close_port(state), do: state

  # Closing the port closes the child's stdin, which is how a stdio server is asked to exit.
  # It does not reap the child, so a helper that ignores EOF is killed by its os pid.
  defp kill(state) do
    _state = hard_close(state)
    :ok
  rescue
    _error -> :ok
  end

  defp hard_close(%{os_pid: os_pid} = state) do
    # Kill while the port still names this child; closing first creates a needless PID-reuse
    # race. `close_port/1` then releases the BEAM resource and makes old port messages stale.

    if is_integer(os_pid) and os_pid > 0 do
      case System.find_executable("kill") do
        nil -> :ok
        exe -> System.cmd(exe, ["-KILL", Integer.to_string(os_pid)], stderr_to_stdout: true)
      end
    end

    state
    |> close_port()
    |> Map.put(:os_pid, nil)
  rescue
    _error -> state |> close_port() |> Map.put(:os_pid, nil)
  end

  ## Snapshots

  defp put_snapshot(state, session_dir, last) do
    seq = state.seq + 1
    snapshots = Map.put(state.snapshots, session_dir, {seq, last})

    snapshots =
      if map_size(snapshots) > @max_sessions do
        {oldest, _} = Enum.min_by(snapshots, fn {_dir, {s, _}} -> s end)
        Map.delete(snapshots, oldest)
      else
        snapshots
      end

    %{state | snapshots: snapshots, seq: seq}
  end

  ## Settings

  defp settings(opts) do
    %{
      max_frame_bytes: setting(opts, :max_frame_bytes),
      handshake_timeout_ms: setting(opts, :handshake_timeout_ms),
      shutdown_grace_ms: setting(opts, :shutdown_grace_ms)
    }
  end

  defp setting(opts, key) do
    case Keyword.get(opts, key) do
      value when is_integer(value) and value > 0 -> value
      _absent -> Desktop.config(key)
    end
  end

  defp normalize_doctor(doctor) when is_map(doctor), do: doctor
  defp normalize_doctor(_other), do: %{}

  defp drop_timer(ref) when is_reference(ref), do: Process.cancel_timer(ref)
  defp drop_timer(_ref), do: :ok

  defp queueable?(state) do
    :queue.len(Map.get(state, :queue, :queue.new())) < @max_queue and
      (state.phase in [:idle, :ready, :handshaking] or
         (state.phase == :broken and now() >= state.broken_until))
  end

  defp maybe_connect(%{phase: phase} = state) when phase in [:idle, :broken], do: connect(state)
  defp maybe_connect(state), do: state

  defp request_item(from, method, params, timeout) do
    caller = elem(from, 0)
    request_ref = make_ref()

    %{
      ref: request_ref,
      from: from,
      caller: caller,
      monitor: Process.monitor(caller),
      method: method,
      params: params,
      expires_at: now() + timeout,
      deadline: Process.send_after(self(), {:request_deadline, request_ref}, timeout)
    }
  end

  defp cleanup_item(item) do
    drop_timer(item.deadline)
    Process.demonitor(item.monitor, [:flush])
    :ok
  end

  defp enqueue(state, item) do
    %{state | queue: :queue.in(item, Map.get(state, :queue, :queue.new()))}
  end

  defp drain(%{phase: :ready, inflight: nil} = state) do
    case :queue.out(Map.get(state, :queue, :queue.new())) do
      {:empty, _queue} ->
        state

      {{:value, item}, rest} ->
        state = %{state | queue: rest}

        case issue_item(state, item) do
          {:ok, state} ->
            state

          {:expired, state} ->
            if Process.alive?(item.caller), do: GenServer.reply(item.from, {:error, :timeout})
            cleanup_item(item)
            drain(state)

          {:error, reason} ->
            cleanup_item(item)
            GenServer.reply(item.from, {:error, :broken})
            go_broken(state, {:transport_closed, reason})
        end
    end
  end

  defp drain(state), do: state

  defp abandon_inflight(state, item) do
    if state.inflight.method == "act" and is_port(state.port) do
      _ = write(state, Codec.notification("cancel", %{}))
    end

    grace =
      Process.send_after(
        self(),
        {:abandon_deadline, state.inflight.id},
        state.settings.shutdown_grace_ms
      )

    put_in(state.inflight, %{
      state.inflight
      | kind: {:abandoned, item.ref},
        deadline: grace
    })
  end

  defp remove_queued(queue, value, key) do
    items = :queue.to_list(queue)

    case Enum.split_while(items, &(Map.fetch!(&1, key) != value)) do
      {before, [item | after_items]} -> {item, :queue.from_list(before ++ after_items)}
      {_all, []} -> {nil, queue}
    end
  end

  defp now, do: System.monotonic_time(:millisecond)
end
