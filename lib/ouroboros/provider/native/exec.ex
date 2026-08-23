defmodule Ouroboros.Provider.Native.Exec do
  @moduledoc """
  One bounded child-process runner for the native provider.

  `grep`, hooks, checks, and the native `bash` tool all cross this boundary. Every child
  runs through `priv/provider-exec` for the workspace umask and through Erlexec in its own
  process group. A deadline signals that whole group with TERM, waits a bounded grace,
  then sends KILL. A shell child does not survive merely because it was backgrounded.

  Output is bounded while the process runs and while it is being drained after a signal.
  stdout and stderr can be merged for ordinary argv commands or retained separately for
  hook contracts. No temporary stderr file exists for an untrusted command to fill.

  `run/3` takes an executable and argv with no shell. `run_shell/2` takes an operator
  command line through `/bin/sh -c`; stdin is supplied through one private temporary file
  so a command that reads to EOF does not wait for an open port.
  """

  @default_timeout_ms 60_000
  @default_max_bytes 1024 * 1024
  @max_timeout_ms 600_000
  @max_max_bytes 64 * 1024 * 1024
  @drain_ms 500
  @exit_drain_ms 50
  @exit_drain_deadline_ms @exit_drain_ms * 4
  @startup_timeout_ms 5_000

  @type result :: %{
          status: integer(),
          output: binary(),
          stderr: binary(),
          timed_out?: boolean(),
          truncated?: boolean()
        }

  @doc """
  Runs `executable` with `args`, with no shell between them.

  Options: `cd`, `env` (`{name, value}` string pairs), `timeout_ms` (default
  #{@default_timeout_ms}, capped at #{@max_timeout_ms}), `max_bytes` (default
  #{@default_max_bytes}).

  stdout and stderr are merged: the callers of this shape want ripgrep's diagnostics
  interleaved where they happened, and none of them reads stderr as a contract.
  """
  @spec run(String.t(), [String.t()], keyword()) :: {:ok, result()} | {:error, term()}
  def run(executable, args, opts \\ []) when is_binary(executable) and is_list(args) do
    with {:ok, wrapper} <- wrapper() do
      spawn_and_collect(wrapper, [executable | args], false, opts)
    end
  end

  @doc """
  Runs one command line through `/bin/sh -c`, with optional stdin and stderr kept apart.

  Same options as `run/3`, plus `stdin`. The result's `stderr` carries whatever the
  command wrote to file descriptor 2, capped like stdout, which is what makes `exit 2`
  usable as a hook's block-with-a-reason.
  """
  @spec run_shell(String.t(), keyword()) :: {:ok, result()} | {:error, term()}
  def run_shell(command, opts \\ []) when is_binary(command) do
    with {:ok, wrapper} <- wrapper(),
         {:ok, stdin_path} <- scratch_file(stdin_of(opts)) do
      script = "exec <" <> shell_quote(stdin_path) <> "\n" <> command

      try do
        spawn_and_collect(wrapper, ["/bin/sh", "-c", script], true, opts)
      after
        _ = File.rm(stdin_path)
      end
    end
  end

  @doc "Where an executable lives on this node's PATH, or `nil`."
  @spec which(String.t()) :: String.t() | nil
  def which(name) when is_binary(name), do: System.find_executable(name)

  # ---------------------------------------------------------------- internals

  alias Jido.Harness.ProcessDriver.Erlexec

  defp spawn_and_collect(wrapper, args, separate_stderr?, opts) do
    timeout = timeout_ms(opts)
    max_bytes = max_bytes(opts)

    options =
      [
        :monitor,
        {:group, 0},
        :kill_group,
        {:stdin, :close},
        {:stdout, self()},
        if(separate_stderr?, do: {:stderr, self()}, else: {:stderr, :stdout})
      ]
      |> maybe_cd(Keyword.get(opts, :cd))
      |> maybe_env(Keyword.get(opts, :env))

    case :exec.run([wrapper | args], options, @startup_timeout_ms) do
      {:ok, exec_pid, os_pid} ->
        state = empty_output()
        deadline = System.monotonic_time(:millisecond) + timeout

        case collect(exec_pid, os_pid, state, max_bytes, deadline) do
          {:ok, output, status} ->
            {:ok, result(output, status, false)}

          {:timeout, output} ->
            output = terminate_group(exec_pid, os_pid, output, max_bytes)
            {:ok, result(output, 124, true)}
        end

      {:error, reason} ->
        {:error, {:spawn_failed, reason}}
    end
  rescue
    error -> {:error, {:spawn_failed, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:spawn_failed, kind, reason}}
  end

  defp terminate_group(exec_pid, os_pid, output, max_bytes) do
    _ = Erlexec.signal(os_pid, :sigterm)
    deadline = System.monotonic_time(:millisecond) + @drain_ms

    case collect(exec_pid, os_pid, output, max_bytes, deadline) do
      {:ok, drained, _status} ->
        drained

      {:timeout, drained} ->
        _ = Erlexec.signal(os_pid, :sigkill)

        case collect(
               exec_pid,
               os_pid,
               drained,
               max_bytes,
               System.monotonic_time(:millisecond) + @drain_ms
             ) do
          {:ok, killed, _status} -> killed
          {:timeout, killed} -> killed
        end
    end
  end

  defp result(output, status, timed_out?) do
    %{
      status: status,
      output: IO.iodata_to_binary(output.stdout),
      stderr: IO.iodata_to_binary(output.stderr),
      timed_out?: timed_out?,
      truncated?: output.truncated?
    }
  end

  defp empty_output do
    %{stdout: [], stdout_bytes: 0, stderr: [], stderr_bytes: 0, truncated?: false}
  end

  defp maybe_cd(options, path) when is_binary(path), do: [{:cd, path} | options]
  defp maybe_cd(options, _other), do: options

  defp maybe_env(options, env) do
    overrides =
      env
      |> List.wrap()
      |> Enum.flat_map(fn
        {name, value} when is_binary(name) and is_binary(value) -> [{name, value}]
        _other -> []
      end)
      |> Map.new()

    # Erlexec's manager was started with the VM and does not observe later
    # `System.put_env/2` calls. Passing the current environment preserves Port.open's
    # per-command inheritance semantics; explicit tool variables win.
    inherited = Map.merge(System.get_env(), overrides)
    [{:env, Map.to_list(inherited)} | options]
  end

  defp collect(exec_pid, os_pid, output, max_bytes, deadline) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {:stdout, ^os_pid, data} ->
        collect(exec_pid, os_pid, append(output, :stdout, data, max_bytes), max_bytes, deadline)

      {:stderr, ^os_pid, data} ->
        collect(exec_pid, os_pid, append(output, :stderr, data, max_bytes), max_bytes, deadline)

      {:DOWN, ^os_pid, :process, ^exec_pid, reason} ->
        now = System.monotonic_time(:millisecond)

        drained =
          drain_after_down(
            os_pid,
            output,
            max_bytes,
            now + @exit_drain_ms,
            now + @exit_drain_deadline_ms
          )

        {:ok, drained, exit_status(reason)}
    after
      remaining -> {:timeout, output}
    end
  end

  defp drain_after_down(os_pid, output, max_bytes, idle_deadline, hard_deadline) do
    now = System.monotonic_time(:millisecond)
    remaining = max(min(idle_deadline, hard_deadline) - now, 0)

    receive do
      {:stdout, ^os_pid, data} ->
        drain_after_down(
          os_pid,
          append(output, :stdout, data, max_bytes),
          max_bytes,
          min(System.monotonic_time(:millisecond) + @exit_drain_ms, hard_deadline),
          hard_deadline
        )

      {:stderr, ^os_pid, data} ->
        drain_after_down(
          os_pid,
          append(output, :stderr, data, max_bytes),
          max_bytes,
          min(System.monotonic_time(:millisecond) + @exit_drain_ms, hard_deadline),
          hard_deadline
        )
    after
      remaining -> output
    end
  end

  defp append(output, stream, data, max_bytes) when is_binary(data) do
    bytes_key = if stream == :stdout, do: :stdout_bytes, else: :stderr_bytes
    used = Map.fetch!(output, bytes_key)
    available = max(max_bytes - used, 0)
    kept = if byte_size(data) <= available, do: data, else: binary_part(data, 0, available)

    output
    |> Map.update!(stream, &[&1, kept])
    |> Map.put(bytes_key, used + byte_size(kept))
    |> Map.update!(:truncated?, &(&1 or byte_size(kept) != byte_size(data)))
  end

  defp exit_status(:normal), do: 0

  defp exit_status({:exit_status, status}) when is_integer(status) do
    case :exec.status(status) do
      {:status, exit_status} -> exit_status
      {:signal, signal, _core?} -> 128 + :exec.signal_to_int(signal)
    end
  rescue
    _error -> status
  end

  defp exit_status(status) when is_integer(status), do: exit_status({:exit_status, status})
  defp exit_status(_reason), do: 1

  defp stdin_of(opts) do
    case Keyword.get(opts, :stdin) do
      value when is_binary(value) -> value
      _absent -> ""
    end
  end

  defp scratch_file(content) do
    name = "ouro-exec-" <> Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)
    path = Path.join(System.tmp_dir!(), name)

    case File.write(path, content) do
      :ok ->
        _ = File.chmod(path, 0o600)
        {:ok, path}

      {:error, reason} ->
        {:error, {:scratch_file_unavailable, reason}}
    end
  end

  defp shell_quote(value), do: "'" <> String.replace(value, "'", "'\\''") <> "'"

  defp wrapper do
    with directory when is_list(directory) <- :code.priv_dir(:ouroboros),
         path = directory |> List.to_string() |> Path.join("provider-exec"),
         {:ok, %File.Stat{type: :regular, mode: mode}} <- File.lstat(path),
         true <- Bitwise.band(mode, 0o111) != 0 do
      {:ok, path}
    else
      failure -> {:error, {:wrapper_unavailable, failure}}
    end
  end

  defp timeout_ms(opts) do
    case Keyword.get(opts, :timeout_ms) do
      value when is_integer(value) and value > 0 -> min(value, @max_timeout_ms)
      _unset -> @default_timeout_ms
    end
  end

  defp max_bytes(opts) do
    case Keyword.get(opts, :max_bytes) do
      value when is_integer(value) and value > 0 -> min(value, @max_max_bytes)
      _unset -> @default_max_bytes
    end
  end
end
