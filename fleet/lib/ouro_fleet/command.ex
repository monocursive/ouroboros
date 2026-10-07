defmodule OuroFleet.Command do
  @moduledoc "Bounded argv-only subprocess adapter. No shell, inherited stdin or unbounded logs."
  def json(executable, args, timeout \\ 60_000) do
    with {:ok, data, status} <- raw(executable, args, timeout) do
      try do
        {:ok, OuroFleet.JSON.decode(data), status}
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
        Port.close(port)
        {:error, "component_response_too_large"}

      {^port, {:exit_status, status}} ->
        data = chunks |> Enum.reverse() |> IO.iodata_to_binary()
        {:ok, data, status}
    after
      remaining ->
        Port.close(port)
        {:error, "component_timeout_outcome_unknown"}
    end
  end
end
