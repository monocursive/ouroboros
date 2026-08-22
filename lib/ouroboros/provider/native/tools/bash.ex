defmodule Ouroboros.Provider.Native.Tools.Bash do
  @moduledoc """
  Run one shell command in the session workspace, bounded in time and in output.

  **Refused entirely under `sandbox_mode: :read_only`, and that is not a conservatism —
  it is the only honest answer.** There is no OS sandbox in this slice (§7 Track C5), so
  nothing here can stop `sh -c` from writing a file; a shell that were allowed under a
  read-only posture would make the label a lie. No sandbox means no shell in read-only.

  Every child goes through `priv/provider-exec`, the same `umask 022` wrapper every
  Harness CLI child already crosses: the managed BEAM runs at `077` so journals stay
  private, and a workspace file a command creates should still be an ordinary `0644`.

  Output follows the pattern Anthropic recommends and every leader implements
  (R3 §2, §8a): 30 KiB inline as head and tail with the middle elided, and the whole
  output written to a file under the session's own directory whose path is returned. A
  model that needs the rest can `read` it; the transcript does not carry it.
  """

  use Jido.Action,
    name: "bash",
    description:
      "Run a shell command in the workspace root. Output is truncated to 30 KiB; the " <>
        "full output is saved to a file whose path is returned.",
    schema: [
      command: [type: :string, required: true, doc: "The command line to run with `sh -c`."],
      timeout_ms: [
        type: :pos_integer,
        default: 120_000,
        doc: "Kill the command after this many milliseconds. Maximum 600000."
      ],
      description: [
        type: :string,
        default: "",
        doc: "A short description of what the command does, shown in the transcript."
      ]
    ]

  @max_timeout_ms 600_000
  @inline_bytes 30 * 1024
  @head_bytes 20 * 1024
  @tail_bytes 10 * 1024
  # A command that produces gigabytes must not take the node with it. The spill file is
  # capped and says where it stopped.
  @max_captured_bytes 64 * 1024 * 1024

  @impl true
  def run(params, context) do
    with :ok <- executable(context.scope),
         {:ok, wrapper} <- wrapper() do
      timeout = min(params.timeout_ms, @max_timeout_ms)

      case execute(wrapper, params.command, context.scope.root, timeout) do
        {:ok, output, status, timed_out?} ->
          {inline, note} = present(output, context)

          {:ok,
           %{
             output: header(status, timed_out?, timeout) <> inline <> note,
             is_error: timed_out? or status != 0
           }}

        {:error, reason} ->
          {:ok, %{output: "bash failed: #{describe(reason)}", is_error: true}}
      end
    else
      {:error, reason} -> {:ok, %{output: "bash refused: #{describe(reason)}", is_error: true}}
    end
  end

  defp executable(%{sandbox_mode: :read_only}), do: {:error, :read_only_sandbox}
  defp executable(_scope), do: :ok

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
        # TERM first so a shell can run its own traps, then close the port, which is
        # what actually reaps the direct child. A process the command detached from its
        # own group can outlive this; that limit is stated in the README rather than
        # pretended away.
        if os_pid, do: System.cmd("/bin/kill", ["-TERM", Integer.to_string(os_pid)], stderr_to_stdout: true)
        drained = drain(port, [], System.monotonic_time(:millisecond) + 500)
        if Port.info(port), do: Port.close(port)
        {:ok, drained, 124, true}
    end
  rescue
    error -> {:error, {:spawn_failed, Exception.message(error)}}
  end

  defp collect(port, acc, size, deadline) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {^port, {:data, data}} ->
        if size >= @max_captured_bytes do
          collect(port, acc, size, deadline)
        else
          collect(port, [acc, data], size + byte_size(data), deadline)
        end

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

  defp header(_status, true, timeout_ms),
    do: "Command timed out after #{timeout_ms} ms and was terminated.\n"

  defp header(0, false, _timeout_ms), do: ""
  defp header(status, false, _timeout_ms), do: "Command exited #{status}.\n"

  defp present(output, _context) when byte_size(output) <= @inline_bytes, do: {output, ""}

  defp present(output, context) do
    head = binary_part(output, 0, @head_bytes)
    tail = binary_part(output, byte_size(output) - @tail_bytes, @tail_bytes)
    elided = byte_size(output) - @head_bytes - @tail_bytes

    inline = head <> "\n… #{elided} bytes elided …\n" <> tail

    case spill(output, context) do
      {:ok, path} ->
        {inline, "\n(full output, #{byte_size(output)} bytes: #{path} — read it if you need the middle)"}

      {:error, _reason} ->
        {inline, "\n(#{elided} bytes could not be spilled to a file and are lost)"}
    end
  end

  defp spill(output, context) do
    case context[:session_dir] do
      dir when is_binary(dir) ->
        name = "bash-" <> Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false) <> ".txt"
        path = Path.join([dir, "output", name])

        with :ok <- File.mkdir_p(Path.dirname(path)),
             :ok <- File.write(path, output),
             :ok <- File.chmod(path, 0o600) do
          {:ok, path}
        end

      _absent ->
        {:error, :no_session_dir}
    end
  end

  defp describe(:read_only_sandbox),
    do:
      "this session runs with sandbox_mode: read_only. There is no OS sandbox in this " <>
        "build, so a shell cannot be made read-only; read_only refuses `bash` entirely"

  defp describe({:wrapper_unavailable, failure}),
    do: "the priv/provider-exec umask wrapper is unusable: #{inspect(failure)}"

  defp describe({:spawn_failed, message}), do: message
end
