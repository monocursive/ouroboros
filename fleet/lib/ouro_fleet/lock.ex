defmodule OuroFleet.Lock do
  @moduledoc "A lifetime flock held by a monitored child; no stale lock-file ownership."
  use GenServer
  def start_link(path), do: GenServer.start_link(__MODULE__, path)

  def init(path) do
    case File.lstat(path) do
      {:error, :enoent} -> :ok
      {:ok, %{type: :regular, links: 1}} -> :ok
      _ -> raise "unsafe fleet lock file"
    end

    Process.flag(:trap_exit, true)

    port =
      Port.open({:spawn_executable, ~c"/usr/bin/flock"}, [
        :binary,
        :exit_status,
        {:args, [~c"--nonblock", ~c"--no-fork", String.to_charlist(path), ~c"/bin/cat"]}
      ])

    Port.command(port, "locked\n")

    receive do
      {^port, {:data, "locked\n"}} ->
        File.chmod!(path, 0o600)
        {:ok, port}

      _ ->
        {:stop, :fleet_store_locked}
    after
      5000 ->
        Port.close(port)
        {:stop, :fleet_lock_timeout}
    end
  end

  def handle_info(_, port), do: {:stop, :fleet_lock_lost, port}

  def terminate(_, port) do
    if Port.info(port), do: Port.close(port)
  end
end
