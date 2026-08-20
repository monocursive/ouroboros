defmodule Ouroboros.RuntimeOwner do
  @moduledoc """
  Owns one runtime's durable data directory for the lifetime of its VM.

  `gateway.json` is a replaceable discovery publication. It can disappear while the
  gateway restarts, or be removed by an operator, without making the journals beside it
  safe for a second runtime. This process therefore claims `runtime.owner` before any
  durable child starts and keeps that independent ownership fact until the owning
  runtime shuts down.

  The claim is a fully written 0600 temporary file hard-linked into place. A hard link is
  the local-filesystem compare-and-create primitive needed here: it fails when the target
  exists and never exposes a partial marker. A dead holder is recovered only by the
  winner of a separate advisory recovery lock held by a trusted native helper. Every
  loser refuses without unlinking, while either a claimant crash or a VM crash releases
  the kernel lock so the next supervised start can retry without manual gate surgery.

  Graceful shutdown removes only a marker whose pid and random VM identity still match
  this owner. A process or VM crash deliberately leaves the marker behind, where the next
  runtime can inspect its pid and recover it only after that pid is dead.
  """

  use GenServer

  import Bitwise

  alias Ouroboros.DataDir

  @marker_name "runtime.owner"
  @recovery_name "runtime.owner.recovery"
  @identity_key {__MODULE__, :vm_identity}
  @helper_env "OUROBOROS_PROCESS_ID_HELPER"
  @trusted_kill_paths ["/bin/kill", "/usr/bin/kill"]
  @trusted_ps_paths ["/bin/ps", "/usr/bin/ps"]

  @doc "Starts the runtime-lifetime owner."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc "The ownership marker a client checks independently of `gateway.json`."
  @spec marker_path(Path.t()) :: Path.t()
  def marker_path(data_dir), do: Path.join(data_dir, @marker_name)

  @doc false
  def claim(server \\ __MODULE__), do: GenServer.call(server, :claim)

  @impl true
  def init(opts) do
    data_dir = Keyword.fetch!(opts, :data_dir)
    DataDir.ensure_private!(data_dir)

    # A supervisor's orderly `:shutdown` is an exit signal. GenServer only reaches
    # terminate/2 for that signal when it traps exits, which is what lets the lifetime
    # marker distinguish a graceful application stop from an untrappable crash.
    Process.flag(:trap_exit, true)

    path = marker_path(data_dir)
    pid = Keyword.get_lazy(opts, :os_pid, &os_pid/0)
    identity = Keyword.get_lazy(opts, :identity, &vm_identity/0)
    birth = Keyword.get_lazy(opts, :birth, fn -> own_birth!(pid) end)
    pid_state = Keyword.get(opts, :pid_state, &pid_state/1)
    birth_state = Keyword.get(opts, :birth_state, &birth_state/2)
    link = Keyword.get(opts, :link, &File.ln/2)
    recovery_lock = Keyword.get(opts, :recovery_lock, &with_recovery_lock/2)
    contents = JSON.encode!(%{"pid" => pid, "owner" => identity, "birth" => birth}) <> "\n"

    result =
      recovery_lock.(data_dir, fn ->
        claim(
          data_dir,
          path,
          contents,
          pid,
          identity,
          birth,
          pid_state,
          birth_state,
          link,
          false,
          true
        )
      end)

    case result do
      :ok ->
        {:ok, %{path: path, pid: pid, identity: identity, birth: birth}}

      {:error, reason} ->
        {:stop, reason}
    end
  end

  # The marker is a lifetime claim, so an owner crash leaves it for this VM's restarted
  # child to recognize. Only an orderly application/supervisor stop releases it.
  @impl true
  def terminate(reason, state) when reason in [:normal, :shutdown] do
    release_if_owner(state)
    :ok
  end

  def terminate({:shutdown, _detail}, state) do
    release_if_owner(state)
    :ok
  end

  def terminate(_reason, _state), do: :ok

  # `System.cmd/3` owns a linked Port while it runs. This process deliberately traps
  # exits so an orderly supervisor shutdown reaches `terminate/2`; that also turns the
  # Port's ordinary completion signal into a mailbox message. GenServer's default
  # handler logs such a message as an error even though the liveness probe succeeded,
  # which made every stale-owner recovery look unhealthy to an operator. The command's
  # exit status has already been returned to `pid_state/1`, so only the linked Port's
  # normal completion is consumed here. Unexpected exits retain GenServer's normal
  # visibility instead of being hidden.
  @impl true
  def handle_call(:claim, _from, state) do
    {:reply, %{pid: state.pid, owner: state.identity, birth: state.birth}, state}
  end

  @impl true
  def handle_info({:EXIT, port, :normal}, state) when is_port(port), do: {:noreply, state}

  defp claim(
         data_dir,
         path,
         contents,
         pid,
         identity,
         birth,
         pid_state,
         birth_state,
         link,
         recovered?,
         recovery_gate_held?
       ) do
    with :ok <- mkdir(data_dir),
         :ok <- ensure_recovery_gate_available(data_dir, recovery_gate_held?) do
      case claim_once(data_dir, path, contents, link) do
        {:claimed, _stat} ->
          :ok

        {:exists, uid} ->
          resolve_existing(
            data_dir,
            path,
            contents,
            pid,
            identity,
            birth,
            uid,
            pid_state,
            birth_state,
            link,
            recovered?
          )

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  defp mkdir(data_dir) do
    DataDir.ensure_private!(data_dir)
    :ok
  rescue
    error -> failure(:runtime_owner_claim_failed, data_dir, Exception.message(error))
  end

  defp ensure_recovery_gate_available(_data_dir, true), do: :ok

  defp ensure_recovery_gate_available(data_dir, false) do
    path = Path.join(data_dir, @recovery_name)

    case File.lstat(path, time: :posix) do
      {:error, :enoent} ->
        :ok

      {:ok, _stat} ->
        failure(
          :runtime_owner_recovery_busy,
          path,
          "a stale-owner recovery is active or was interrupted. Do not remove this gate " <>
            "while any claimant may still be running. Inspect #{marker_path(data_dir)}; " <>
            "only after its pid is confirmed absent (not merely inaccessible) and no " <>
            "Ouroboros startup is using #{data_dir}, remove this recovery gate and retry. " <>
            "Leave runtime.owner in place for atomic recovery"
        )

      {:error, reason} ->
        failure(:runtime_owner_recovery_gate_unreadable, path, reason)
    end
  end

  # The destination appears only after the complete, private inode exists. The temporary
  # name is removed on every arm, including an unsupported-hard-link error and a lost
  # claim race.
  defp claim_once(data_dir, path, contents, link) do
    temporary =
      Path.join(
        data_dir,
        ".#{@marker_name}.#{os_pid()}.#{System.unique_integer([:positive, :monotonic])}.tmp"
      )

    try do
      with :ok <- write_temporary(temporary, contents),
           {:ok, stat} <- stat_temporary(temporary) do
        case link.(temporary, path) do
          :ok -> {:claimed, stat}
          {:error, :eexist} -> {:exists, stat.uid}
          {:error, reason} -> failure(:runtime_owner_atomic_claim_failed, path, reason)
        end
      end
    after
      _ = File.rm(temporary)
    end
  end

  defp write_temporary(path, contents) do
    with :ok <- File.write(path, contents, [:binary, :exclusive, :sync]),
         :ok <- File.chmod(path, 0o600) do
      :ok
    else
      {:error, reason} -> failure(:runtime_owner_claim_failed, path, reason)
    end
  end

  defp stat_temporary(path) do
    case File.lstat(path, time: :posix) do
      {:ok, stat} -> {:ok, stat}
      {:error, reason} -> failure(:runtime_owner_claim_failed, path, reason)
    end
  end

  defp resolve_existing(
         data_dir,
         path,
         contents,
         pid,
         identity,
         birth,
         uid,
         pid_state,
         birth_state,
         link,
         recovered?
       ) do
    case read_marker(path, uid) do
      {:ok, %{pid: ^pid, owner: ^identity, birth: ^birth}} ->
        # The owner process restarted inside the same VM. Its random identity lives in
        # persistent_term, so a different runtime cannot acquire this arm by pid alone.
        :ok

      {:ok, marker} ->
        case incarnation_state(marker, pid_state, birth_state) do
          :alive ->
            failure(
              :runtime_data_dir_owned,
              path,
              "runtime pid #{marker.pid} already owns this data directory"
            )

          :dead when not recovered? ->
            recover_stale(
              data_dir,
              path,
              contents,
              pid,
              identity,
              birth,
              pid_state,
              birth_state,
              link,
              marker
            )

          :dead ->
            failure(
              :runtime_owner_recovery_raced,
              path,
              "the stale owner was replaced during the single recovery attempt; retry"
            )

          {:unknown, reason} ->
            failure(
              :runtime_owner_liveness_unknown,
              path,
              "could not determine whether runtime pid #{marker.pid} is alive: #{inspect(reason)}"
            )

          other ->
            failure(
              :runtime_owner_liveness_unknown,
              path,
              "the pid liveness check returned #{inspect(other)} for runtime pid #{marker.pid}"
            )
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp recover_stale(
         data_dir,
         path,
         contents,
         pid,
         identity,
         birth,
         pid_state,
         birth_state,
         link,
         marker
       ) do
    recover_stale_while_gated(
      data_dir,
      path,
      contents,
      pid,
      identity,
      birth,
      pid_state,
      birth_state,
      link,
      marker
    )
  end

  # Every claimant that observed the same stale marker must first win this separate
  # O_EXCL-style gate. The winner re-reads and re-checks liveness while holding it; a
  # loser never reaches File.rm/1 and therefore cannot unlink the winner's new marker.
  defp recover_stale_while_gated(
         data_dir,
         path,
         contents,
         pid,
         identity,
         birth,
         pid_state,
         birth_state,
         link,
         stale
       ) do
    case read_marker(path, stale.stat.uid) do
      {:ok, current} ->
        if same_marker?(current, stale) do
          replace_if_still_dead(
            data_dir,
            path,
            contents,
            pid,
            identity,
            birth,
            pid_state,
            birth_state,
            link,
            current
          )
        else
          recovery_raced(path)
        end

      {:error, _reason} ->
        recovery_raced(path)
    end
  end

  defp replace_if_still_dead(
         data_dir,
         path,
         contents,
         pid,
         identity,
         birth,
         pid_state,
         birth_state,
         link,
         marker
       ) do
    case incarnation_state(marker, pid_state, birth_state) do
      :dead ->
        remove_stale_and_claim(
          data_dir,
          path,
          contents,
          pid,
          identity,
          birth,
          pid_state,
          birth_state,
          link,
          marker
        )

      :alive ->
        failure(
          :runtime_data_dir_owned,
          path,
          "runtime pid #{marker.pid} became live while stale recovery was starting"
        )

      {:unknown, reason} ->
        failure(
          :runtime_owner_liveness_unknown,
          path,
          "could not recheck runtime pid #{marker.pid} during recovery: #{inspect(reason)}"
        )

      other ->
        failure(
          :runtime_owner_liveness_unknown,
          path,
          "the pid liveness recheck returned #{inspect(other)} for runtime pid #{marker.pid}"
        )
    end
  end

  defp remove_stale_and_claim(
         data_dir,
         path,
         contents,
         pid,
         identity,
         birth,
         pid_state,
         birth_state,
         link,
         marker
       ) do
    case File.lstat(path, time: :posix) do
      {:ok, current} ->
        if same_file?(current, marker.stat) do
          case File.rm(path) do
            :ok ->
              claim(
                data_dir,
                path,
                contents,
                pid,
                identity,
                birth,
                pid_state,
                birth_state,
                link,
                true,
                true
              )

            {:error, reason} ->
              failure(:runtime_owner_stale_recovery_failed, path, reason)
          end
        else
          recovery_raced(path)
        end

      {:error, _reason} ->
        recovery_raced(path)
    end
  end

  defp recovery_raced(path) do
    failure(
      :runtime_owner_recovery_raced,
      path,
      "the owner marker changed before stale recovery; retry"
    )
  end

  defp read_marker(path, uid) do
    with {:ok, stat} <- File.lstat(path, time: :posix),
         :ok <- validate_stat(path, stat, uid),
         {:ok, contents} <- File.read(path),
         {:ok, decoded} <- decode(path, contents),
         {:ok, marker} <- validate_marker(path, decoded) do
      {:ok, Map.put(marker, :stat, stat)}
    else
      {:error, {:runtime_owner_marker_invalid, _message} = reason} -> {:error, reason}
      {:error, reason} -> failure(:runtime_owner_marker_unreadable, path, reason)
    end
  end

  defp validate_stat(_path, %File.Stat{type: :regular, uid: uid, mode: mode}, uid)
       when (mode &&& 0o777) == 0o600,
       do: :ok

  defp validate_stat(path, %File.Stat{type: type}, _uid) when type != :regular,
    do: failure(:runtime_owner_marker_invalid, path, "marker is not a regular file")

  defp validate_stat(path, %File.Stat{uid: actual}, expected) when actual != expected,
    do:
      failure(
        :runtime_owner_marker_invalid,
        path,
        "marker belongs to uid #{actual}, not this runtime's uid #{expected}"
      )

  defp validate_stat(path, %File.Stat{mode: mode}, _uid),
    do:
      failure(
        :runtime_owner_marker_invalid,
        path,
        "marker mode must be 0600, got #{Integer.to_string(mode &&& 0o777, 8)}"
      )

  defp decode(path, contents) do
    case JSON.decode(contents) do
      {:ok, decoded} -> {:ok, decoded}
      {:error, reason} -> failure(:runtime_owner_marker_invalid, path, inspect(reason))
    end
  end

  defp validate_marker(path, %{"pid" => pid, "owner" => owner, "birth" => birth})
       when is_integer(pid) and pid > 0 and is_binary(owner) and byte_size(owner) > 0 and
              is_binary(birth) do
    if byte_size(birth) in 1..256 and String.match?(birth, ~r/\A[A-Za-z0-9:_-]+\z/) do
      {:ok, %{pid: pid, owner: owner, birth: birth}}
    else
      failure(:runtime_owner_marker_invalid, path, "process birth identity is malformed")
    end
  end

  # Upgrade compatibility: a live legacy marker remains fail-closed because PID liveness
  # cannot distinguish reuse. A definitively absent legacy PID may still be recovered.
  defp validate_marker(_path, %{"pid" => pid, "owner" => owner})
       when is_integer(pid) and pid > 0 and is_binary(owner) and byte_size(owner) > 0,
       do: {:ok, %{pid: pid, owner: owner, birth: nil}}

  defp validate_marker(path, _decoded),
    do:
      failure(
        :runtime_owner_marker_invalid,
        path,
        "marker must contain a positive integer pid, a nonblank owner identity, and an optional bounded process birth identity"
      )

  defp release_if_owner(%{path: path, pid: pid, identity: identity, birth: birth}) do
    case File.read(path) do
      {:ok, contents} ->
        case JSON.decode(contents) do
          {:ok, %{"pid" => ^pid, "owner" => ^identity, "birth" => ^birth}} -> File.rm(path)
          _not_ours -> :ok
        end

      {:error, _reason} ->
        :ok
    end
  end

  defp same_file?(left, right) do
    left.uid == right.uid and left.major_device == right.major_device and
      left.inode == right.inode
  end

  defp same_marker?(left, right) do
    left.pid == right.pid and left.owner == right.owner and left.birth == right.birth and
      same_file?(left.stat, right.stat)
  end

  defp incarnation_state(%{pid: pid, birth: birth}, _pid_state, birth_state)
       when is_binary(birth),
       do: birth_state.(pid, birth)

  defp incarnation_state(%{pid: pid}, pid_state, _birth_state), do: pid_state.(pid)

  defp own_birth!(pid) do
    case helper_birth(pid) do
      {:ok, birth} ->
        birth

      {:error, reason} ->
        if test_environment?() do
          "test:#{pid}:#{System.unique_integer([:positive, :monotonic])}"
        else
          raise "Ouroboros needs its trusted ouro process-incarnation helper before opening durable state: #{inspect(reason)}. Start this runtime through `ouro` or its generated fleet service."
        end
    end
  end

  defp birth_state(pid, expected) do
    case pid_state(pid) do
      :dead ->
        :dead

      :alive ->
        case helper_birth(pid) do
          {:ok, ^expected} -> :alive
          {:ok, _different_birth} -> :dead
          {:error, reason} -> {:unknown, reason}
        end

      {:unknown, reason} ->
        {:unknown, reason}
    end
  end

  defp helper_birth(pid) do
    with {:ok, helper} <- trusted_helper() do
      case System.cmd(
             helper,
             ["process-birth", "--pid", Integer.to_string(pid)],
             stderr_to_stdout: true,
             env: [{"PATH", ""}]
           ) do
        {output, 0} -> validate_birth_output(output)
        {output, status} -> {:error, {:process_birth_helper_failed, status, String.trim(output)}}
      end
    end
  rescue
    error -> {:error, Exception.message(error)}
  end

  defp validate_birth_output(output) do
    birth = String.trim(output)

    if byte_size(birth) in 1..256 and
         String.match?(birth, ~r/\A[A-Za-z0-9:_-]+\z/) do
      {:ok, birth}
    else
      {:error, {:invalid_process_birth, birth}}
    end
  end

  defp with_recovery_lock(data_dir, fun) do
    case trusted_helper() do
      {:ok, helper} ->
        with_helper_recovery_lock(helper, data_dir, fun)

      {:error, reason} ->
        if test_environment?(),
          do: fun.(),
          else: failure(:runtime_owner_recovery_helper_unavailable, data_dir, reason)
    end
  end

  defp with_helper_recovery_lock(helper, data_dir, fun) do
    path = Path.join(data_dir, @recovery_name)

    port =
      Port.open(
        {:spawn_executable, String.to_charlist(helper)},
        [
          :binary,
          :exit_status,
          :use_stdio,
          :stderr_to_stdout,
          {:line, 1024},
          args: ["hold-runtime-recovery-lock", "--path", path],
          env: [{~c"PATH", ~c""}]
        ]
      )

    receive do
      {^port, {:data, {:eol, "locked"}}} ->
        run_while_helper_locked(port, path, fun)

      {^port, {:data, {_line, output}}} ->
        close_port(port)
        failure(:runtime_owner_recovery_busy, path, String.trim(output))

      {^port, {:exit_status, status}} ->
        failure(:runtime_owner_recovery_busy, path, "helper exited with status #{status}")
    after
      5_000 ->
        close_port(port)

        failure(
          :runtime_owner_recovery_busy,
          path,
          "helper did not acquire the lock in 5 seconds"
        )
    end
  rescue
    error -> failure(:runtime_owner_recovery_helper_failed, data_dir, Exception.message(error))
  end

  defp run_while_helper_locked(port, path, fun) do
    owner = self()
    result_ref = make_ref()

    {worker, monitor} =
      spawn_monitor(fn ->
        send(owner, {result_ref, fun.()})
      end)

    receive do
      {^result_ref, result} ->
        Process.demonitor(monitor, [:flush])
        close_port(port)
        result

      {^port, {:exit_status, status}} ->
        stop_claim_worker(worker, monitor, result_ref)

        failure(
          :runtime_owner_recovery_lock_lost,
          path,
          "lock helper exited with status #{status} during the atomic owner claim"
        )

      {:EXIT, ^port, reason} ->
        stop_claim_worker(worker, monitor, result_ref)

        failure(
          :runtime_owner_recovery_lock_lost,
          path,
          "lock helper exited during the atomic owner claim: #{inspect(reason)}"
        )

      {:DOWN, ^monitor, :process, ^worker, reason} ->
        close_port(port)
        failure(:runtime_owner_claim_failed, path, "claim worker exited: #{inspect(reason)}")
    end
  end

  # The recovery lock disappearing must stop the only code that may still remove or
  # replace runtime.owner before this GenServer returns an error. Drain a result sent just
  # before the helper exit too, so no private worker message can later reach handle_info/2.
  defp stop_claim_worker(worker, monitor, result_ref) do
    Process.exit(worker, :kill)
    await_claim_worker_down(worker, monitor, result_ref)
  end

  defp await_claim_worker_down(worker, monitor, result_ref) do
    receive do
      {^result_ref, _discarded_result} ->
        await_claim_worker_down(worker, monitor, result_ref)

      {:DOWN, ^monitor, :process, ^worker, _reason} ->
        :ok
    end
  end

  defp close_port(port) do
    if Port.info(port) != nil do
      Port.close(port)
    end

    :ok
  rescue
    ArgumentError -> :ok
  end

  defp trusted_helper do
    case System.get_env(@helper_env) do
      path when is_binary(path) ->
        path = String.trim(path)

        case File.lstat(path) do
          {:ok, %File.Stat{type: :regular, mode: mode}} when (mode &&& 0o111) != 0 ->
            if Path.type(path) == :absolute,
              do: {:ok, path},
              else: {:error, {@helper_env, :not_absolute}}

          _unsafe ->
            {:error, {@helper_env, :not_executable_regular_file}}
        end

      _missing ->
        {:error, {@helper_env, :missing}}
    end
  end

  defp test_environment? do
    Code.ensure_loaded?(Mix) and function_exported?(Mix, :env, 0) and Mix.env() == :test
  rescue
    _mix_not_started -> false
  catch
    _kind, _reason -> false
  end

  # `kill -0` sends no signal and changes no process state; it is only the Unix liveness
  # and permission query. Ownership recovery must not resolve this executable through
  # inherited PATH: project-local shims could otherwise claim a live pid is absent and
  # authorize deletion of its marker. An unavailable trusted checker fails closed.
  defp pid_state(pid) do
    with {:ok, executable} <- trusted_system_executable(:kill, @trusted_kill_paths) do
      case System.cmd(executable, ["-0", Integer.to_string(pid)], stderr_to_stdout: true) do
        {_output, 0} -> :alive
        {_output, _status} -> pid_state_after_failed_kill(pid)
      end
    end
  rescue
    error -> {:unknown, Exception.message(error)}
  end

  # kill(2) reports both ESRCH and EPERM as a non-zero command status. EPERM still means
  # the pid is alive, so consult the process table before declaring a marker stale.
  defp pid_state_after_failed_kill(pid) do
    with {:ok, executable} <- trusted_system_executable(:ps, @trusted_ps_paths) do
      case System.cmd(
             executable,
             ["-p", Integer.to_string(pid), "-o", "pid="],
             stderr_to_stdout: true
           ) do
        {output, 0} ->
          if String.trim(output) == Integer.to_string(pid),
            do: :alive,
            else: {:unknown, {:unexpected_ps_output, output}}

        {_output, 1} ->
          :dead

        {output, status} ->
          {:unknown, {:ps_failed, status, String.trim(output)}}
      end
    end
  rescue
    error -> {:unknown, Exception.message(error)}
  end

  defp trusted_system_executable(command, candidates) do
    case Enum.find(candidates, &trusted_executable?/1) do
      nil -> {:unknown, {:trusted_system_executable_unavailable, command, candidates}}
      path -> {:ok, path}
    end
  end

  defp trusted_executable?(path) do
    case File.stat(path) do
      {:ok, %File.Stat{type: :regular, mode: mode}} -> (mode &&& 0o111) != 0
      _missing_or_unsafe -> false
    end
  end

  defp os_pid do
    case Integer.parse(System.pid()) do
      {pid, ""} -> pid
      _other -> :os.getpid() |> List.to_string() |> String.to_integer()
    end
  end

  defp vm_identity do
    case :persistent_term.get(@identity_key, nil) do
      nil ->
        identity = Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)
        :persistent_term.put(@identity_key, identity)
        identity

      identity ->
        identity
    end
  end

  defp failure(kind, path, detail), do: {:error, {kind, "#{path}: #{format_detail(detail)}"}}

  defp format_detail(reason) when is_atom(reason), do: :file.format_error(reason) |> to_string()
  defp format_detail(detail) when is_binary(detail), do: detail
  defp format_detail(detail), do: inspect(detail)
end
