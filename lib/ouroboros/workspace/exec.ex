defmodule Ouroboros.Workspace.Exec do
  @moduledoc """
  One command, run in a session's admitted workspace as the operator's own act (B7).

  This is not a tool. No model asks for it, no provider is told about it, and nothing
  here decides whether it may run — `Ouroboros.Interactive.Task` answers that question
  before this module is called, and records the attempt in the effect ledger before the
  first byte is written. What lives here is the mechanics: spawn without a shell in the
  middle, bound the time, bound the output, and spill the rest to a private file.

  ## Why the wrapper

  The command text goes to `/bin/sh -c` as an *argument* to a `priv/provider-exec`
  wrapper spawned with `{:spawn_executable, …}`, exactly as the native agent's `bash`
  tool does. `{:spawn, …}` would hand the string to a shell that Erlang chooses, which
  is one more interpreter between the operator's bytes and the process that runs them.

  ## Bounds, and the one this cannot enforce

  Ten minutes by default and by ceiling; 30 KiB of output inline as a head and a tail
  with the middle elided; everything beyond that written to a `0600` file under the
  session's own data directory and named in the result. Capture stops at 64 MiB so a
  command producing gigabytes cannot take the node with it.

  A process that detaches from its own process group can outlive the timeout. The
  timeout terminates the shell this runtime started, and `Port.close/1` reaps its direct
  child; a daemon it forked is not this runtime's to kill, and the README says so rather
  than implying otherwise.
  """

  @default_timeout_ms 10 * 60 * 1_000
  @max_timeout_ms 10 * 60 * 1_000
  @inline_bytes 30 * 1024
  @head_bytes 20 * 1024
  @tail_bytes 10 * 1024
  @max_captured_bytes 64 * 1024 * 1024

  # What the next turn's `<ouroboros-runtime>` envelope carries per command. Small on
  # purpose: the excerpt is a reminder that the operator did something, and the whole
  # output is on the session's own log for a client to fetch.
  @excerpt_bytes 512

  @typedoc "What one operator command did."
  @type result :: %{
          command_digest: String.t(),
          cwd: String.t(),
          exit_status: integer(),
          timed_out: boolean(),
          duration_ms: non_neg_integer(),
          output: String.t(),
          output_bytes: non_neg_integer(),
          excerpt: String.t(),
          spilled: String.t() | nil,
          spill_error: String.t() | nil
        }

  @doc "The default and maximum wall clock one operator command may take."
  @spec timeout_ms() :: pos_integer()
  def timeout_ms, do: @default_timeout_ms

  @doc "A stable digest of a command line, for the ledger and the transcript."
  @spec digest(String.t()) :: String.t()
  def digest(command) when is_binary(command),
    do: :sha256 |> :crypto.hash(command) |> Base.encode16(case: :lower)

  @doc """
  Runs `command` through `/bin/sh -c` in `cwd` and returns a bounded report.

  Never raises and never returns an error tuple for a command that merely failed: a
  non-zero exit is a result, not a fault. `{:error, reason}` is reserved for this runtime
  being unable to start the command at all.
  """
  @spec run(String.t(), String.t(), keyword()) :: {:ok, result()} | {:error, term()}
  def run(command, cwd, opts \\ []) when is_binary(command) and is_binary(cwd) do
    timeout = opts |> Keyword.get(:timeout_ms, @default_timeout_ms) |> min(@max_timeout_ms)

    with {:ok, wrapper} <- wrapper() do
      started = System.monotonic_time(:millisecond)

      case execute(wrapper, command, cwd, timeout) do
        {:ok, output, status, timed_out?} ->
          elapsed = System.monotonic_time(:millisecond) - started
          {inline, spilled, spill_error} = present(output, opts)

          {:ok,
           %{
             command_digest: digest(command),
             cwd: cwd,
             exit_status: status,
             timed_out: timed_out?,
             duration_ms: elapsed,
             output: inline,
             output_bytes: byte_size(output),
             excerpt: excerpt(output),
             spilled: spilled,
             spill_error: spill_error
           }}

        {:error, _reason} = error ->
          error
      end
    end
  end

  @doc """
  The directory this session's spill files live in, created `0700`.

  Under the node's data directory where one is configured, and under the system temp
  directory where none is — the same fallback the native agent's own paths take, and the
  same admission: a spill in a temp directory does not survive a reboot.
  """
  @spec spill_dir(String.t()) :: {:ok, String.t()} | {:error, term()}
  def spill_dir(session_id) when is_binary(session_id) do
    with {:ok, safe} <- safe_component(session_id) do
      path = Path.join([root_dir(), safe, "exec"])

      case File.mkdir_p(path) do
        :ok ->
          _ = File.chmod(path, 0o700)
          {:ok, path}

        {:error, reason} ->
          {:error, {:spill_dir_unavailable, reason}}
      end
    end
  end

  # A session id becomes a directory name, so it is held to the same rule the native
  # agent holds its own to: an id that is not plainly a name does not get to describe a
  # path. Refused rather than sanitised — a mangled id would collide with another.
  defp safe_component(session_id) do
    if String.match?(session_id, ~r/\A[A-Za-z0-9._:-]{1,128}\z/) and
         not String.starts_with?(session_id, ".") do
      {:ok, String.replace(session_id, ":", "-")}
    else
      {:error, {:unsafe_session_id, session_id}}
    end
  end

  defp root_dir do
    case Application.get_env(:ouroboros, :data_dir) do
      path when is_binary(path) and path != "" ->
        Path.join([path, "sessions"])

      _absent ->
        Path.join(System.tmp_dir!(), "ouroboros-sessions-#{:erlang.phash2(node())}")
    end
  end

  defp wrapper do
    with directory when is_list(directory) <- :code.priv_dir(:ouroboros),
         path = directory |> List.to_string() |> Path.join("provider-exec"),
         {:ok, %File.Stat{type: :regular, mode: mode}} <- File.lstat(path),
         true <- Bitwise.band(mode, 0o111) != 0 do
      {:ok, path}
    else
      failure -> {:error, {:wrapper_unavailable, inspect(failure, limit: 4)}}
    end
  end

  defp execute(wrapper, command, cwd, timeout_ms) do
    port =
      Port.open(
        {:spawn_executable, String.to_charlist(wrapper)},
        [
          :binary,
          :exit_status,
          :use_stdio,
          :stderr_to_stdout,
          :hide,
          {:args, [~c"/bin/sh", ~c"-c", String.to_charlist(command)]},
          {:cd, String.to_charlist(cwd)}
        ]
      )

    os_pid =
      case Port.info(port, :os_pid) do
        {:os_pid, pid} -> pid
        _gone -> nil
      end

    deadline = System.monotonic_time(:millisecond) + timeout_ms

    case collect(port, [], 0, deadline) do
      {:ok, output, status} ->
        {:ok, output, status, false}

      :timeout ->
        # TERM first so a shell can run its own traps, then close the port, which is what
        # actually reaps the direct child.
        if os_pid,
          do:
            System.cmd("/bin/kill", ["-TERM", Integer.to_string(os_pid)], stderr_to_stdout: true)

        drained = drain(port, [], System.monotonic_time(:millisecond) + 500)
        if Port.info(port), do: Port.close(port)
        {:ok, drained, 124, true}
    end
  rescue
    error -> {:error, {:spawn_failed, Exception.message(error)}}
  catch
    :exit, reason -> {:error, {:spawn_failed, inspect(reason, limit: 4)}}
  end

  defp collect(port, acc, size, deadline) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {^port, {:data, data}} ->
        # Over the cap the port keeps draining and this stops accumulating: abandoning
        # the port would leave a live process with nobody reading it.
        if size >= @max_captured_bytes,
          do: collect(port, acc, size, deadline),
          else: collect(port, [acc, data], size + byte_size(data), deadline)

      {^port, {:exit_status, status}} ->
        {:ok, IO.iodata_to_binary(acc), status}
    after
      remaining -> :timeout
    end
  end

  defp drain(port, acc, deadline) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {^port, {:data, data}} -> drain(port, [acc, data], deadline)
      {^port, {:exit_status, _status}} -> IO.iodata_to_binary(acc)
    after
      remaining -> IO.iodata_to_binary(acc)
    end
  end

  defp present(output, _opts) when byte_size(output) <= @inline_bytes, do: {output, nil, nil}

  defp present(output, opts) do
    head = binary_part(output, 0, @head_bytes)
    tail = binary_part(output, byte_size(output) - @tail_bytes, @tail_bytes)
    elided = byte_size(output) - @head_bytes - @tail_bytes
    inline = head <> "\n… #{elided} bytes elided …\n" <> tail

    case spill(output, opts) do
      {:ok, path} -> {inline, path, nil}
      {:error, reason} -> {inline, nil, inspect(reason, limit: 4)}
    end
  end

  defp spill(output, opts) do
    case Keyword.get(opts, :spill_dir) do
      dir when is_binary(dir) ->
        name = "exec-" <> Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false) <> ".txt"
        path = Path.join(dir, name)

        with :ok <- File.mkdir_p(dir),
             :ok <- File.write(path, output),
             :ok <- File.chmod(path, 0o600) do
          {:ok, path}
        end

      _absent ->
        {:error, :no_spill_dir}
    end
  end

  # The tail, not the head: what an operator wants next turn is what the command ended
  # up saying. Control characters go because this text is rendered into the runtime
  # envelope, and the byte bound backs off to a whole codepoint.
  defp excerpt(output) do
    output
    |> tail_bytes(@excerpt_bytes)
    |> String.replace(~r/\p{Cc}/u, " ")
    |> String.trim()
  end

  defp tail_bytes(output, limit) when byte_size(output) <= limit, do: output

  defp tail_bytes(output, limit) do
    output
    |> binary_part(byte_size(output) - limit, limit)
    |> whole_codepoints()
  end

  defp whole_codepoints(""), do: ""

  defp whole_codepoints(binary) do
    if String.valid?(binary),
      do: binary,
      else: whole_codepoints(binary_slice(binary, 1, byte_size(binary) - 1))
  end
end
