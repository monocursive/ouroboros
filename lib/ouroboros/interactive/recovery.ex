defmodule Ouroboros.Interactive.Recovery do
  @moduledoc false

  use GenServer

  alias Ouroboros.Interactive.{State, Store, Task}

  @interval 1_000

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name_option(Keyword.get(opts, :name, __MODULE__)))
  end

  @impl true
  def init(opts) do
    interval = Keyword.get(opts, :interval, @interval)
    {:ok, %{interval: interval}, {:continue, :recover}}
  end

  @impl true
  def handle_continue(:recover, state) do
    recover_sessions()
    schedule_recovery(state.interval)
    {:noreply, state}
  end

  @impl true
  def handle_info(:recover, state) do
    recover_sessions()
    schedule_recovery(state.interval)
    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp recover_sessions do
    case {Process.whereis(Ouroboros.Interactive.Registry),
          Process.whereis(Ouroboros.Interactive.TaskSupervisor), safe_list()} do
      {registry, supervisor, sessions}
      when is_pid(registry) and is_pid(supervisor) and is_list(sessions) ->
        sessions
        |> Enum.filter(fn %State{} = session ->
          session.node == node() and not State.terminal?(session)
        end)
        |> Enum.each(fn session -> safe_start_child(supervisor, session.id) end)

      _unavailable ->
        :ok
    end
  end

  defp safe_start_child(supervisor, id) do
    case DynamicSupervisor.start_child(supervisor, {Task, id}) do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _pid}} -> :ok
      {:error, _reason} -> :ok
    end
  rescue
    _error -> :ok
  catch
    :exit, _reason -> :ok
  end

  defp safe_list do
    Store.list()
  rescue
    _error -> {:error, :store_unavailable}
  catch
    :exit, reason -> {:error, reason}
  end

  defp schedule_recovery(interval), do: Process.send_after(self(), :recover, interval)

  defp name_option(nil), do: []
  defp name_option(name), do: [name: name]
end
