defmodule Ouroboros.Fleet.Deployment.Launcher do
  @moduledoc """
  The one place the BEAM decides where `ouro` is, and the only two ways it runs it.

  The launcher that started this runtime exports `OUROBOROS_PROCESS_ID_HELPER` as the
  absolute path of the `ouro` executable it ran (seam S1; `tui/src/runtime.rs` sets it and
  `Ouroboros.RuntimeOwner` already reads it for its liveness checks). This module reads
  exactly that and never consults `PATH`: a deployment spawns a process that will be handed
  an SSH credential, and resolving its executable through inherited environment is how a
  project-local shim becomes the thing holding the password.

  The same validation `RuntimeOwner.trusted_helper/0` applies is applied here — absolute,
  a regular file by `lstat` so a symlink is refused rather than followed, and executable by
  somebody. A runtime started some other way has no `ouro`, and that is reported as
  `ouro_path_unknown` rather than guessed at.

  Both entry points take an argv list. Nothing here builds a shell string, and no caller
  may: `System.cmd/3` execs the file directly.
  """

  import Bitwise

  alias Ouroboros.DataDir
  alias Ouroboros.Fleet.Deployment.Journal

  @helper_env "OUROBOROS_PROCESS_ID_HELPER"

  # A handful of strings: a host, an account, a port, two paths and an identity reference.
  # A request past this is a caller this build refuses rather than one it hands to another
  # process.
  @max_request_bytes 64 * 1024

  # `fleet_setup::SCHEMA`. The worker refuses a request whose schema it does not know and
  # refuses unknown keys outright, so this number and that one moving apart is a broken
  # deployment rather than a quiet one — which is the direction it should fail in.
  @request_schema 1

  # What `ouro` may print into this runtime's heap before it is stopped. A device inventory
  # for a large tailnet is tens of kilobytes; half a megabyte is generous, and past it the
  # child is not answering the question that was asked.
  @max_output_bytes 512 * 1024

  # The same absolute paths `Ouroboros.RuntimeOwner` holds its liveness checker to. A
  # deadline that resolved `kill` through an inherited PATH would be a deadline a
  # project-local shim could disarm.
  @trusted_kill_paths ["/bin/kill", "/usr/bin/kill"]

  @typedoc "Why this runtime cannot name an `ouro` to run."
  @type path_error ::
          {:ouro_path_unknown, :missing | :not_absolute | :not_executable_regular_file}

  @doc """
  The absolute `ouro` this runtime was started by.

  Never a `PATH` lookup, and never a relative path resolved against the daemon's working
  directory — both are ambient state a deployment must not inherit.
  """
  @spec executable() :: {:ok, Path.t()} | {:error, path_error()}
  def executable do
    case System.get_env(@helper_env) do
      value when is_binary(value) ->
        path = String.trim(value)

        cond do
          path == "" -> {:error, {:ouro_path_unknown, :missing}}
          Path.type(path) != :absolute -> {:error, {:ouro_path_unknown, :not_absolute}}
          true -> regular_executable(path)
        end

      _missing ->
        {:error, {:ouro_path_unknown, :missing}}
    end
  end

  defp regular_executable(path) do
    case File.lstat(path) do
      {:ok, %File.Stat{type: :regular, mode: mode}} when (mode &&& 0o111) != 0 -> {:ok, path}
      _unsafe -> {:error, {:ouro_path_unknown, :not_executable_regular_file}}
    end
  end

  @doc """
  Runs `ouro` with this argv and returns its stdout, bounded by `timeout` milliseconds.

  The command runs in a throwaway monitored process rather than in the caller, because
  `System.cmd/3` owns a linked Port and the caller here is often a process that traps exits.
  When the deadline expires that process is killed, which closes the Port, which is what
  reaps the operating-system child — `System.cmd/3` has no timeout of its own.

  stderr is left attached to the runtime's own stderr rather than folded into stdout: these
  callers parse the stdout as JSON, and a warning line mixed into it would be reported as
  unreadable output instead of as the warning it is.
  """
  @spec run([String.t()], pos_integer(), pos_integer()) ::
          {:ok, String.t()}
          | {:error, path_error()}
          | {:error, {:ouro_failed, integer(), String.t()}}
          | {:error, {:ouro_crashed, term()}}
          | {:error, {:ouro_output_too_large, pos_integer()}}
          | {:error, :ouro_timeout}
  def run(args, timeout, max_bytes \\ @max_output_bytes)
      when is_list(args) and is_integer(timeout) and timeout > 0 and is_integer(max_bytes) do
    with {:ok, ouro} <- executable() do
      case command(ouro, args, timeout, max_bytes) do
        {:ok, {output, 0}} -> {:ok, output}
        {:ok, {output, status}} -> {:error, {:ouro_failed, status, excerpt(output)}}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  @doc """
  Starts a detached worker for one operation and reads the line it prints (seam S2).

  `ouro fleet worker start` forks the worker into its own session and process group, points
  its stdio at a private log, and exits 0 after printing one JSON line naming the socket it
  will listen on and the instance identity that distinguishes it from a recycled pid. This
  returns that line decoded; it does not connect, and it holds nothing of the worker's
  lifetime — the worker outlives this runtime by design.

  ## The request travels in a private file, not on argv

  Seam S2 fixes the argv at `--operation` and `--data-dir`, and seam S3's client operations
  are a closed list with no verb that describes a target. The request an operator made —
  which machine, which SSH account, which port, which identity *reference*, which paths —
  therefore has to reach the worker some third way, and it goes in
  `<data dir>/deploy/<operation>.request.json`.

  Not on the command line, and the reason is `ps`. An argv is readable by every local user
  on both platforms this ships to; a target hostname and an SSH account name are not
  secrets in the sense the spec's one list means, but they are exactly the reconnaissance
  that makes the next attempt cheaper, and there is no reason to publish them to a shell
  account that has no business with this deployment. The file is 0600 in a 0700 directory,
  written whole before the worker exists, and retained for recovery after a worker crash.

  Written atomically — an exclusive temporary inode chmodded before a byte goes in, then
  renamed into place — so the worker never opens a half-written request, and never a
  request whose mode was briefly the umask's idea. Canonical JSON with sorted keys, so the
  same request twice is the same bytes twice. Bounded at 64 KiB: this is a handful of
  strings, and a request larger than that is a caller this build should refuse rather than
  hand to another process.

  When the launch itself fails — a nonzero exit, a crash, a ceiling — this removes the file
  again, because nothing is coming to read it. When the launch succeeds the file is the
  worker's, even if this runtime cannot then parse what it printed.

  A resume passes `nil` and writes nothing: the worker retains its request and journal, and
  re-stating a target would be a second chance to state a different one.
  """
  @spec spawn_worker(String.t(), Path.t(), map() | nil, pos_integer()) ::
          {:ok, %{socket: Path.t(), instance: String.t()}}
          | {:error, path_error()}
          | {:error, {:worker_spawn_failed, term()}}
  def spawn_worker(operation, data_dir, request, timeout)
      when is_binary(operation) and is_binary(data_dir) and (is_map(request) or is_nil(request)) do
    args = ["fleet", "worker", "start", "--operation", operation, "--data-dir", data_dir]
    path = Journal.request_path(data_dir, operation)

    with :ok <- publish_request(path, operation, request) do
      case run(args, timeout) do
        {:ok, output} ->
          decode_spawn(output)

        {:error, {:ouro_path_unknown, _detail} = reason} ->
          discard_request(path, request)
          {:error, reason}

        {:error, reason} ->
          discard_request(path, request)
          {:error, {:worker_spawn_failed, reason}}
      end
    end
  end

  defp publish_request(_path, _operation, nil), do: :ok

  defp publish_request(path, operation, request) do
    # `schema` and `operation` are stamped here rather than by the caller: the operation id
    # is minted by the broker a moment before this runs, and the schema is a fact about the
    # wire rather than about the request somebody made.
    document = Map.merge(request, %{"schema" => @request_schema, "operation" => operation})
    bytes = canonical(document) |> IO.iodata_to_binary()

    cond do
      byte_size(bytes) > @max_request_bytes ->
        {:error, {:worker_spawn_failed, :request_too_large}}

      true ->
        with :ok <- private_deploy_dir(Path.dirname(path)) do
          write_private_atomic(path, bytes)
        end
    end
  end

  defp discard_request(_path, nil), do: :ok
  # The removal's own failure is not the caller's problem: the launch already failed, and
  # a request file this could not unlink is a private file in a private directory that
  # nothing will read.
  defp discard_request(path, _request) do
    _ = File.rm(path)
    :ok
  end

  # `chmod` rather than a refusal, uniquely here: 0700 only ever *removes* access, the
  # directory is this uid's own, and both the broker and the worker create it. Narrowing is
  # the one direction a privacy repair is safe in without asking an operator first.
  defp private_deploy_dir(dir) do
    with :ok <- File.mkdir_p(dir), :ok <- File.chmod(dir, 0o700) do
      :ok
    else
      {:error, reason} -> {:error, {:worker_spawn_failed, {:deploy_dir_unwritable, reason}}}
    end
  end

  # Exclusive temporary inode, chmodded before the first byte, then renamed. The rename is
  # what makes it atomic for the reader; the chmod-before-write is what keeps the umask from
  # deciding who may read a target hostname for the length of one write.
  defp write_private_atomic(path, bytes) do
    tmp = path <> ".tmp-" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)

    with {:ok, io} <- File.open(tmp, [:write, :exclusive, :binary]),
         :ok <- File.chmod(tmp, 0o600),
         :ok <- IO.binwrite(io, bytes),
         :ok <- File.close(io),
         :ok <- File.rename(tmp, path) do
      :ok
    else
      {:error, reason} ->
        _ = File.rm(tmp)
        {:error, {:worker_spawn_failed, {:request_unwritable, reason}}}
    end
  end

  # Sorted keys, no whitespace. Two identical requests produce two identical files, which is
  # what lets a duplicate `prepare` be recognised as one by looking rather than by guessing.
  defp canonical(value) when is_map(value) do
    inner =
      value
      |> Enum.sort_by(fn {key, _value} -> to_string(key) end)
      |> Enum.map(fn {key, inner} ->
        [JSON.encode_to_iodata!(to_string(key)), ?:, canonical(inner)]
      end)
      |> Enum.intersperse(?,)

    [?{, inner, ?}]
  end

  defp canonical(value) when is_list(value),
    do: [?[, value |> Enum.map(&canonical/1) |> Enum.intersperse(?,), ?]]

  defp canonical(value), do: JSON.encode_to_iodata!(value)

  # The worker prints exactly one line. Anything else — an empty stdout, a second line, a
  # socket path that is not absolute — is a worker this build cannot talk to, and saying so
  # is better than connecting to whatever the string happened to name.
  defp decode_spawn(output) do
    with [line | _rest] <- output |> String.split("\n", trim: true),
         {:ok, %{"socket" => socket, "instance" => instance}}
         when is_binary(socket) and is_binary(instance) <- JSON.decode(line),
         true <- Path.type(socket) == :absolute and instance != "" do
      {:ok, %{socket: socket, instance: instance}}
    else
      _unreadable -> {:error, {:worker_spawn_failed, :unreadable_worker_line}}
    end
  end

  # The Port is opened here rather than through `System.cmd/3`, for two reasons `System.cmd`
  # cannot give:
  #
  #   * **The child is reaped on a deadline.** `System.cmd/3` has no timeout, and killing
  #     the Elixir process that owns the Port closes the Port — which, for a child that is
  #     ignoring its closed stdout, leaves the operating-system process running (review F5).
  #     Owning the Port means holding its `os_pid`, and the deadline sends that pid SIGKILL
  #     through the same trusted absolute `kill` the ownership marker uses.
  #   * **The output is bounded as it arrives.** `System.cmd/3` accumulates whatever the
  #     child prints; a fake `ouro` printing 64 MiB put 64 MiB in this runtime's heap before
  #     anything looked at it (review F6). Here the accumulator is checked per chunk and the
  #     child is killed the moment it goes past the cap.
  #
  # stderr is deliberately not redirected: these callers parse stdout as JSON, and a warning
  # folded into it would be reported as unreadable output rather than as the warning it is.
  defp command(executable, args, timeout, max_bytes) do
    port =
      Port.open({:spawn_executable, executable}, [
        :binary,
        :exit_status,
        :hide,
        :stream,
        {:args, args}
      ])

    os_pid =
      case Port.info(port, :os_pid) do
        {:os_pid, pid} -> pid
        _gone -> nil
      end

    deadline = System.monotonic_time(:millisecond) + timeout
    collect(port, os_pid, deadline, max_bytes, [], 0)
  end

  defp collect(port, os_pid, deadline, max_bytes, chunks, size) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {^port, {:data, chunk}} ->
        size = size + byte_size(chunk)

        if size > max_bytes do
          reap(port, os_pid)
          {:error, {:ouro_output_too_large, size}}
        else
          collect(port, os_pid, deadline, max_bytes, [chunk | chunks], size)
        end

      {^port, {:exit_status, status}} ->
        {:ok, {chunks |> Enum.reverse() |> IO.iodata_to_binary(), status}}

      {:EXIT, ^port, reason} ->
        reap(port, os_pid)
        {:error, {:ouro_crashed, reason}}
    after
      remaining ->
        reap(port, os_pid)
        {:error, :ouro_timeout}
    end
  end

  # Close the Port, then kill the process it spawned. In that order, and both: closing alone
  # leaves a child that is not reading its stdin and not writing its stdout exactly where it
  # was.
  #
  # Only the child's own pid, never its process group — the child is not in a session of its
  # own (it must not be; that is the *worker's* job, done behind `fleet worker start`), so
  # its process group is this runtime's, and signalling that would take the BEAM down with
  # it. A grandchild the child spawned therefore survives, which is stated here rather than
  # implied away.
  defp reap(port, os_pid) do
    _ = if Port.info(port), do: Port.close(port)

    if os_pid do
      case DataDir.trusted_executable!(@trusted_kill_paths, "kill") do
        kill -> System.cmd(kill, ["-KILL", Integer.to_string(os_pid)], stderr_to_stdout: true)
      end
    end

    :ok
  rescue
    _unavailable -> :ok
  catch
    _kind, _reason -> :ok
  end

  # A failed command's output is an operator-facing diagnostic, so it is bounded rather
  # than passed through: it reaches a JSON-RPC `data` field and a log line.
  defp excerpt(output) when is_binary(output),
    do: output |> String.trim() |> String.slice(0, 2_000)
end
