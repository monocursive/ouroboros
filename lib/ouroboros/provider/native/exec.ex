defmodule Ouroboros.Provider.Native.Exec do
  @moduledoc """
  One bounded child process, for everything in this provider that is not `bash`.

  `grep` shells out to ripgrep, a hook runs an operator's command with JSON on its
  stdin, and `[checks]` runs a typecheck. Each needs the same four things and no more:
  a deadline that actually reaps the child, a cap on how many bytes it may return, an
  exit status, and — for hooks — stderr kept apart from stdout, because the hook
  contract makes stderr the reason text of a block.

  `System.cmd/3` gives none of those. It has no timeout at all, so a compile that hangs
  would hang the turn, and a `Task.shutdown/2` around it kills the Elixir process while
  leaving the OS child running. So this is a port, like
  `Ouroboros.Provider.Native.Tools.Bash`, with the same TERM-then-close reaping and the
  same honest limit: a child that detaches from its process group outlives its deadline.

  ## Two shapes

  `run/3` takes an executable and an argv list. Nothing is interpreted by a shell, which
  is what makes it safe to hand a model-supplied regular expression to ripgrep.

  `run_shell/2` takes a command line and runs it through `/bin/sh -c`, for hooks and
  `[checks]`, whose commands are written by an operator and are shell by definition.
  Only that shape carries stdin and separates stderr, and it does both through the
  filesystem rather than through the port: a port cannot signal end-of-file on stdin
  without being closed, and a hook that reads until EOF would otherwise wait for its own
  deadline. The script is therefore prefixed with `exec <` and `exec 2>` redirects on
  their own lines, into private `0600` temporary files, so the operator's command text
  is passed through unrewritten.

  Every child goes through `priv/provider-exec`, the `umask 022` wrapper every Harness
  CLI child already crosses, so a file a hook creates is an ordinary `0644` rather than
  inheriting the managed BEAM's `077`.
  """

  @default_timeout_ms 60_000
  @default_max_bytes 1024 * 1024
  @max_timeout_ms 600_000
  @max_max_bytes 16 * 1024 * 1024
  @drain_ms 500

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
      spawn_and_collect(wrapper, [executable | args], nil, opts)
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
         {:ok, error_path} <- scratch_file(""),
         {:ok, stdin_path} <- scratch_file(stdin_of(opts)) do
      script =
        "exec <" <>
          shell_quote(stdin_path) <>
          "\nexec 2>" <> shell_quote(error_path) <> "\n" <> command

      try do
        spawn_and_collect(wrapper, ["/bin/sh", "-c", script], error_path, opts)
      after
        _ = File.rm(error_path)
        _ = File.rm(stdin_path)
      end
    end
  end

  @doc "Where an executable lives on this node's PATH, or `nil`."
  @spec which(String.t()) :: String.t() | nil
  def which(name) when is_binary(name), do: System.find_executable(name)

  # ---------------------------------------------------------------- internals

  defp spawn_and_collect(wrapper, args, error_path, opts) do
    timeout = timeout_ms(opts)
    max_bytes = max_bytes(opts)

    port_options =
      [
        :binary,
        :exit_status,
        :use_stdio,
        :hide,
        {:args, Enum.map(args, &String.to_charlist/1)}
      ]
      |> merge_stderr(error_path)
      |> maybe_cd(Keyword.get(opts, :cd))
      |> maybe_env(Keyword.get(opts, :env))

    port = Port.open({:spawn_executable, String.to_charlist(wrapper)}, port_options)

    os_pid =
      case Port.info(port, :os_pid) do
        {:os_pid, pid} -> pid
        _gone -> nil
      end

    deadline = System.monotonic_time(:millisecond) + timeout

    case collect(port, [], 0, max_bytes, deadline, false) do
      {:ok, output, truncated?, status} ->
        {:ok, result(output, read_errors(error_path, max_bytes), status, false, truncated?)}

      {:timeout, acc, truncated?} ->
        if os_pid,
          do:
            System.cmd("/bin/kill", ["-TERM", Integer.to_string(os_pid)], stderr_to_stdout: true)

        drained = drain(port, acc, System.monotonic_time(:millisecond) + @drain_ms)
        if Port.info(port), do: Port.close(port)

        {:ok,
         result(
           IO.iodata_to_binary(drained),
           read_errors(error_path, max_bytes),
           124,
           true,
           truncated?
         )}
    end
  rescue
    error -> {:error, {:spawn_failed, Exception.message(error)}}
  end

  defp result(output, stderr, status, timed_out?, truncated?) do
    %{
      status: status,
      output: output,
      stderr: stderr,
      timed_out?: timed_out?,
      truncated?: truncated?
    }
  end

  defp merge_stderr(options, nil), do: [:stderr_to_stdout | options]
  defp merge_stderr(options, _error_path), do: options

  defp maybe_cd(options, path) when is_binary(path),
    do: [{:cd, String.to_charlist(path)} | options]

  defp maybe_cd(options, _other), do: options

  defp maybe_env(options, env) when is_list(env) and env != [] do
    converted =
      Enum.flat_map(env, fn
        {name, value} when is_binary(name) and is_binary(value) ->
          [{String.to_charlist(name), String.to_charlist(value)}]

        _other ->
          []
      end)

    if converted == [], do: options, else: [{:env, converted} | options]
  end

  defp maybe_env(options, _other), do: options

  defp collect(port, acc, size, max_bytes, deadline, truncated?) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {^port, {:data, data}} ->
        if size >= max_bytes do
          collect(port, acc, size, max_bytes, deadline, true)
        else
          collect(port, [acc, data], size + byte_size(data), max_bytes, deadline, truncated?)
        end

      {^port, {:exit_status, status}} ->
        {:ok, IO.iodata_to_binary(acc), truncated?, status}
    after
      remaining -> {:timeout, acc, truncated?}
    end
  end

  defp drain(port, acc, deadline) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {^port, {:data, data}} -> drain(port, [acc, data], deadline)
      {^port, {:exit_status, _status}} -> acc
    after
      remaining -> acc
    end
  end

  defp read_errors(nil, _max_bytes), do: ""

  defp read_errors(path, max_bytes) do
    case File.read(path) do
      {:ok, content} when byte_size(content) <= max_bytes -> content
      {:ok, content} -> binary_part(content, 0, max_bytes)
      {:error, _reason} -> ""
    end
  end

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
