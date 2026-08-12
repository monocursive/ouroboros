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

  # A rest_for_one cascade can take the store or the supervisor down beneath this
  # process. Recovery is periodic, so an unavailable dependency waits for the next
  # tick instead of burning restart intensity.
  defp recover_all do
    case safe_list() do
      snapshots when is_list(snapshots) ->
        Enum.each(snapshots, &recover/1)

      {:error, _reason} ->
        :ok
    end
  end

  defp safe_list do
    Store.list()
  rescue
    _error -> {:error, :store_unavailable}
  catch
    :exit, _reason -> {:error, :store_unavailable}
  end

  defp recover(%Snapshot{status: status} = snapshot) when status in [:active, :closing] do
    if Ouroboros.Team.whereis(snapshot.id) == nil do
      _ = safe_start_child(snapshot)
    end

    :ok
  end

  defp recover(%Snapshot{}), do: :ok

  defp safe_start_child(snapshot) do
    DynamicSupervisor.start_child(
      Ouroboros.Team.Supervisor,
      {Server,
       id: snapshot.id,
       coordinator_id: snapshot.coordinator_id,
       cleanup_agents: snapshot.cleanup_agents?}
    )
  rescue
    _error -> {:error, :supervisor_unavailable}
  catch
    :exit, _reason -> {:error, :supervisor_unavailable}
  end
end
