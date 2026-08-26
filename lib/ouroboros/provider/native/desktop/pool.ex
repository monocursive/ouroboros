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

  @typedoc "What `status/1` reports about the helper."
  @type status :: %{
          phase: :handshaking | :ready | :broken,
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
  Starts the node's helper pool **detached** from the caller.

  Unlinked on purpose: the singleton must outlive the transient tool task that first needs
  it, and there is no supervisor above it in this phase. A crash is recovered by the next
  `Ouroboros.Provider.Native.Desktop.pool/0`, which starts a fresh one — the snapshot map is
  rebuildable by design.
  """
  @spec start(keyword()) :: GenServer.on_start()
  def start(opts) do
    GenServer.start(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc """
  Issues one request to the helper and waits at most `timeout_ms` for the answer.

  Never raises and never exits the caller: a dead helper, a busy pool, a helper still
  handshaking, and a helper that simply does not answer are all error tuples.
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
      denied_app_ids: Keyword.get(opts, :denied_app_ids) || Desktop.denied_app_ids(),
      settings: settings(opts),
      port: nil,
      os_pid: nil,
      buffer: <<>>,
      noise: 0,
      next_id: 1,
      phase: :broken,
      inflight: nil,
      broken_until: 0,
      broken_reason: nil,
      doctor: nil,
      snapshots: %{},
      seq: 0
    }

    {:ok, connect(state)}
  end

  @impl true
  def handle_call({:request, _method, _params, _timeout}, _from, %{inflight: inflight} = state)
      when inflight != nil and state.phase == :ready,
      do: {:reply, {:error, :busy}, state}

  def handle_call({:request, method, params, timeout}, from, %{phase: :ready} = state) do
    case issue(state, method, params, {:caller, from}, timeout) do
      {:ok, state} ->
        {:noreply, state}

      {:error, reason} ->
        {:reply, {:error, reason}, go_broken(state, {:transport_closed, reason})}
    end
  end

  def handle_call({:request, _method, _params, _timeout}, _from, %{phase: :handshaking} = state),
    do: {:reply, {:error, :starting}, state}

  def handle_call({:request, _method, _params, _timeout}, _from, %{phase: :broken} = state) do
    if now() >= state.broken_until,
      do: {:reply, {:error, :reconnecting}, connect(state)},
      else: {:reply, {:error, :broken}, state}
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

  def handle_info({:deadline, id}, %{inflight: %{id: id, kind: {:caller, from}}} = state) do
    GenServer.reply(from, {:error, :timeout})
    {:noreply, %{state | inflight: nil}}
  end

  def handle_info({:deadline, _stale_id}, state), do: {:noreply, state}

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
    state = close_port(state)

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
    cancel(inflight.deadline)
    route(kind, answer(frame), %{state | inflight: nil})
  end

  # A frame with no matching in-flight id — a late response to a timed-out request, or a
  # helper-initiated message this phase does not serve — is ignored rather than acted on.
  defp handle_frame(_frame, state), do: state

  defp route(:handshake, {:ok, doctor}, state) do
    %{state | phase: :ready, doctor: normalize_doctor(doctor)}
  end

  defp route(:handshake, {:error, reason}, state),
    do: go_broken(state, {:handshake_failed, reason})

  defp route({:caller, from}, reply, state) do
    GenServer.reply(from, reply)
    state
  end

  defp answer(%{"error" => %{} = error}),
    do: {:error, {:rpc_error, Map.get(error, "code"), Map.get(error, "message")}}

  defp answer(%{"result" => result}), do: {:ok, result}
  defp answer(_frame), do: {:error, {:malformed_result, "neither result nor error"}}

  defp issue(state, method, params, kind, timeout_ms) do
    {id, state} = take_id(state)

    case write(state, Codec.request(id, method, params)) do
      :ok ->
        ref = Process.send_after(self(), {:deadline, id}, timeout_ms)
        {:ok, %{state | inflight: %{id: id, kind: kind, deadline: ref}}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp take_id(state), do: {state.next_id, %{state | next_id: state.next_id + 1}}

  # Mark broken and answer whoever was waiting. The pool keeps running: it owns the snapshot
  # map, which a live session still needs, and the next call after the cooldown reconnects.
  defp go_broken(state, reason) do
    if state.inflight do
      cancel(state.inflight.deadline)

      case state.inflight.kind do
        {:caller, from} -> GenServer.reply(from, {:error, :broken})
        :handshake -> :ok
      end
    end

    Logger.debug(fn -> "computer-use helper broken: #{inspect(reason, limit: 10)}" end)

    %{
      close_port(state)
      | phase: :broken,
        inflight: nil,
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
  defp serve_args(state) do
    [~c"serve"] ++
      Enum.flat_map(state.denied_app_ids, fn id -> [~c"--deny-app", String.to_charlist(id)] end)
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
    %{os_pid: os_pid} = close_port(state)

    if is_integer(os_pid) and os_pid > 0 do
      case System.find_executable("kill") do
        nil -> :ok
        exe -> System.cmd(exe, ["-KILL", Integer.to_string(os_pid)], stderr_to_stdout: true)
      end
    end

    :ok
  rescue
    _error -> :ok
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
      handshake_timeout_ms: setting(opts, :handshake_timeout_ms)
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

  defp cancel(ref) when is_reference(ref), do: Process.cancel_timer(ref)
  defp cancel(_ref), do: :ok

  defp now, do: System.monotonic_time(:millisecond)
end
