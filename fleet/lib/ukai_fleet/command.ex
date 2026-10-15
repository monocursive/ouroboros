defmodule UkaiFleet.Command do
  @moduledoc "Bounded argv-only subprocess adapter. No shell, inherited stdin or unbounded logs."
  def json(executable, args, timeout \\ 60_000) do
    with {:ok, data, status} <- raw(executable, args, timeout) do
      try do
        {:ok, UkaiFleet.JSON.decode(data), status}
      rescue
        _ -> {:error, "component_response_invalid"}
      end
    end
  end

  def raw(executable, args, timeout \\ 60_000) do
    port =
      Port.open({:spawn_executable, String.to_charlist(executable)}, [
        :binary,
        :exit_status,
        :use_stdio,
        :hide,
        {:args, Enum.map(args, &String.to_charlist/1)}
      ])

    deadline = System.monotonic_time(:millisecond) + timeout
    collect(port, [], 0, deadline)
  end

  defp collect(port, chunks, size, deadline) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {^port, {:data, bytes}} when size + byte_size(bytes) <= 1_048_576 ->
        collect(port, [bytes | chunks], size + byte_size(bytes), deadline)

      {^port, {:data, _bytes}} ->
        stop(port)
        {:error, "component_response_too_large"}

      {^port, {:exit_status, status}} ->
        data = chunks |> Enum.reverse() |> IO.iodata_to_binary()
        {:ok, data, status}
    after
      remaining ->
        stop(port)
        {:error, "component_timeout_outcome_unknown"}
    end
  end

  # Closing a port only closes its pipes, which a child that is not writing never
  # notices: it would keep running after its outcome was already reported unknown. So
  # the child is killed first. Only that child is signalled, not anything it started.
  defp stop(port) do
    with {:os_pid, pid} <- Port.info(port, :os_pid) do
      System.cmd("/bin/kill", ["-KILL", Integer.to_string(pid)], stderr_to_stdout: true)
    end

    # The dying child's exit status closes the port on its own, possibly first.
    try do
      Port.close(port)
    rescue
      ArgumentError -> :ok
    end

    flush(port)
  end

  # Drop what the port delivered before it closed, so it never reaches the caller's
  # mailbox as a stray message.
  defp flush(port) do
    receive do
      {^port, _} -> flush(port)
    after
      0 -> :ok
    end
  end
end
