defmodule Ouroboros.Fleet.Deployment.Launcher do
  @moduledoc """
  The one place the BEAM decides where `ouro` is, and the environment it runs it in.

  The launcher that started this runtime exports `OUROBOROS_PROCESS_ID_HELPER` as the
  absolute path of the `ouro` executable it ran (`tui/src/runtime.rs` sets it and
  `Ouroboros.RuntimeOwner` already reads it for its liveness checks). This module reads
  exactly that and never consults `PATH`: a deployment spawns a process that will be handed
  an SSH credential, and resolving its executable through inherited environment is how a
  project-local shim becomes the thing holding the password.

  The same validation `RuntimeOwner.trusted_helper/0` applies is applied here — absolute,
  a regular file by `lstat` so a symlink is refused rather than followed, and executable by
  somebody. A runtime started some other way has no `ouro`, and that is reported as
  `ouro_path_unknown` rather than guessed at.

  Every entry point takes an argv list. Nothing here builds a shell string, and no caller
  may: the file is exec'd directly.
  """

  import Bitwise

  alias Ouroboros.DataDir

  @helper_env "OUROBOROS_PROCESS_ID_HELPER"

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
  @spec run([String.t()], pos_integer(), keyword()) ::
          {:ok, String.t()}
          | {:error, path_error()}
          | {:error, {:ouro_failed, integer(), String.t()}}
          | {:error, {:ouro_crashed, term()}}
          | {:error, {:ouro_output_too_large, pos_integer()}}
          | {:error, :ouro_timeout}
  def run(args, timeout, opts \\ [])
      when is_list(args) and is_integer(timeout) and timeout > 0 and is_list(opts) do
    max_bytes = Keyword.get(opts, :max_bytes, @max_output_bytes)

    with {:ok, ouro} <- executable() do
      case command(ouro, args, timeout, max_bytes, Keyword.get(opts, :data_dir)) do
        {:ok, {output, 0}} -> {:ok, output}
        {:ok, {output, status}} -> {:error, {:ouro_failed, status, excerpt(output)}}
        {:error, reason} -> {:error, reason}
      end
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
  defp command(executable, args, timeout, max_bytes, data_dir) do
    port =
      Port.open({:spawn_executable, executable}, [
        :binary,
        :exit_status,
        :hide,
        :stream,
        {:args, args},
        {:env, child_env(data_dir)}
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
  # Only the child's own pid, never its process group — a bounded read's child shares this
  # runtime's process group, and signalling that would take the BEAM down with it. A
  # grandchild the child spawned therefore survives, which is stated here rather than
  # implied away. Nothing on this path is the deployment port program: that one is never
  # signalled, because outliving this runtime is what it is for (§8).
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

  @doc """
  The environment a deployment port program is given, and the only one it is given.

  The program is handed an SSH credential. An inherited environment is how a secret in this
  runtime's env — a CI token, a canary, anything `OUROBOROS_*` did not name — becomes a
  secret in the process that holds the password. Keep an allowlist and unset every other key
  explicitly: Port `:env` replaces only the names it is given.

  `data_dir` is stamped on top when one is given, because the §8 argv carries no
  `--data-dir`: the program finds the journal it is to write the way every other `ouro`
  command does, and this runtime's durable directory is the one it must find rather than
  whatever the daemon happened to inherit.
  """
  @spec child_env(Path.t() | nil) :: [{charlist(), charlist() | false}]
  def child_env(data_dir \\ nil) do
    inherited = Enum.map(System.get_env(), fn {key, value} -> env_pair(key, value) end)

    case data_dir do
      dir when is_binary(dir) and dir != "" ->
        name = ~c"OUROBOROS_DATA_DIR"

        [{name, String.to_charlist(dir)} | Enum.reject(inherited, &(elem(&1, 0) == name))]

      _absent ->
        inherited
    end
  end

  defp env_pair(key, value) do
    name = String.to_charlist(key)

    if allowed_env?(key), do: {name, String.to_charlist(value)}, else: {name, false}
  end

  defp allowed_env?(key) when is_binary(key) do
    key in ~w(PATH HOME USER LOGNAME LANG TMPDIR SSH_AUTH_SOCK) or
      String.starts_with?(key, "LC_") or
      String.starts_with?(key, "XDG_") or
      String.starts_with?(key, "OUROBOROS_")
  end
end
