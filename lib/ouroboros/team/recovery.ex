defmodule Ouroboros.Team.Recovery do
  @moduledoc false

  use GenServer

  alias Ouroboros.Team.{Server, Snapshot, Store}

  @interval 1_000

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @impl true
  def init(opts) do
    state = %{interval: Keyword.get(opts, :interval, @interval)}
    recover_all()
    Process.send_after(self(), :recover, state.interval)
    {:ok, state}
  end

  @impl true
  def handle_info(:recover, state) do
    recover_all()
    Process.send_after(self(), :recover, state.interval)
    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp recover_all do
    case Store.list() do
      snapshots when is_list(snapshots) ->
        Enum.each(snapshots, &recover/1)

      {:error, _reason} ->
        :ok
    end
  end

  defp recover(%Snapshot{status: status} = snapshot) when status in [:active, :closing] do
    if Ouroboros.Team.whereis(snapshot.id) == nil do
      _ =
        DynamicSupervisor.start_child(
          Ouroboros.Team.Supervisor,
          {Server,
           id: snapshot.id,
           coordinator_id: snapshot.coordinator_id,
           cleanup_agents: snapshot.cleanup_agents?}
        )
    end

    :ok
  end

  defp recover(%Snapshot{}), do: :ok
end
