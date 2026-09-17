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

  @helper_env "OUROBOROS_PROCESS_ID_HELPER"

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
  @spec run([String.t()], pos_integer()) ::
          {:ok, String.t()}
          | {:error, path_error()}
          | {:error, {:ouro_failed, integer(), String.t()}}
          | {:error, {:ouro_crashed, term()}}
          | {:error, :ouro_timeout}
  def run(args, timeout) when is_list(args) and is_integer(timeout) and timeout > 0 do
    with {:ok, ouro} <- executable() do
      case command(ouro, args, timeout) do
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

  ## `--request-json`, and why it is argv

  Seam S2 fixes `--operation` and `--data-dir`, and seam S3's client operations are a closed
  list with no verb that describes a target. The request an operator made — which machine,
  which SSH account, which port, which identity *reference*, which paths — therefore has to
  reach the worker some third way, and this passes it as one argument of canonical JSON.

  That is a deliberate choice rather than an oversight. The spec's own retention list makes
  host, user, port, identity reference and paths the things a deployment is *allowed* to
  keep; the one list of places a secret may never appear names command arguments first, and
  nothing in this object is a secret — an identity is referred to by name, never by key
  material, and a password or passphrase only ever travels inside a `respond` frame on the
  socket. An argv the operator can read in `ps` is a feature for a non-secret request.

  A resume passes `nil`: the worker already has its journal, and re-stating a target would be
  a second chance to state a different one.
  """
  @spec spawn_worker(String.t(), Path.t(), map() | nil, pos_integer()) ::
          {:ok, %{socket: Path.t(), instance: String.t()}}
          | {:error, path_error()}
          | {:error, {:worker_spawn_failed, term()}}
  def spawn_worker(operation, data_dir, request, timeout)
      when is_binary(operation) and is_binary(data_dir) and (is_map(request) or is_nil(request)) do
    args =
      ["fleet", "worker", "start", "--operation", operation, "--data-dir", data_dir] ++
        request_args(request)

    case run(args, timeout) do
      {:ok, output} -> decode_spawn(output)
      {:error, {:ouro_path_unknown, _detail} = reason} -> {:error, reason}
      {:error, reason} -> {:error, {:worker_spawn_failed, reason}}
    end
  end

  defp request_args(nil), do: []
  defp request_args(request), do: ["--request-json", JSON.encode!(request)]

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

  defp command(executable, args, timeout) do
    caller = self()
    ref = make_ref()

    {worker, monitor} =
      spawn_monitor(fn ->
        send(caller, {ref, System.cmd(executable, args, stderr_to_stdout: false)})
      end)

    receive do
      {^ref, result} ->
        Process.demonitor(monitor, [:flush])
        {:ok, result}

      {:DOWN, ^monitor, :process, ^worker, reason} ->
        {:error, {:ouro_crashed, reason}}
    after
      timeout ->
        Process.demonitor(monitor, [:flush])
        Process.exit(worker, :kill)
        {:error, :ouro_timeout}
    end
  end

  # A failed command's output is an operator-facing diagnostic, so it is bounded rather
  # than passed through: it reaches a JSON-RPC `data` field and a log line.
  defp excerpt(output) when is_binary(output),
    do: output |> String.trim() |> String.slice(0, 2_000)

  defp excerpt(_other), do: ""
end
