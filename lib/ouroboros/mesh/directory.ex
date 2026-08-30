defmodule Ouroboros.Mesh.Directory do
  @moduledoc false

  use GenServer

  @scope Ouroboros.Mesh.Scope
  @retry_ms 25

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @spec register(String.t(), pid()) :: :ok | {:error, term()}
  def register(id, pid) when is_binary(id) and is_pid(pid) do
    GenServer.call(__MODULE__, {:register, id, pid})
  end

  @spec group(String.t()) :: {:ouroboros_agent, String.t()}
  def group(id), do: {:ouroboros_agent, id}

  @impl true
  def init(_opts) do
    Process.send_after(self(), :reconcile_all, 0)
    {:ok, %{by_id: %{}, by_ref: %{}}}
  end

  @impl true
  def handle_call({:register, id, pid}, _from, state) do
    case register_local(id, pid, state) do
      {:ok, next_state} -> {:reply, :ok, next_state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_info(:reconcile_all, state) do
    next_state =
      Enum.reduce(Ouroboros.Jido.list_agents(), state, fn {id, pid}, acc ->
        case register_local(id, pid, acc) do
          {:ok, registered} -> registered
          {:error, _reason} -> acc
        end
      end)

    {:noreply, next_state}
  end

  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    case Map.pop(state.by_ref, ref) do
      {nil, _by_ref} ->
        {:noreply, state}

      {id, by_ref} ->
        Process.send_after(self(), {:reconcile, id}, @retry_ms)
        {:noreply, %{state | by_ref: by_ref, by_id: Map.delete(state.by_id, id)}}
    end
  end

  def handle_info({:reconcile, id}, state) do
    case Ouroboros.Jido.whereis(id) do
      pid when is_pid(pid) ->
        case register_local(id, pid, state) do
          {:ok, next_state} -> {:noreply, next_state}
          {:error, _reason} -> {:noreply, state}
        end

      nil ->
        {:noreply, state}
    end
  end

  defp register_local(_id, pid, _state) when node(pid) != node(), do: {:error, :not_local}

  defp register_local(id, pid, state) do
    case Map.get(state.by_id, id) do
      {^pid, _ref} ->
        {:ok, state}

      _other ->
        with true <- Process.alive?(pid),
             :ok <- join_once(id, pid) do
          state = drop_previous_monitor(id, pid, state)
          ref = Process.monitor(pid)

          {:ok,
           %{
             state
             | by_id: Map.put(state.by_id, id, {pid, ref}),
               by_ref: Map.put(state.by_ref, ref, id)
           }}
        else
          # `join_once/2` answers `:ok` or nothing at all — `:pg.join/3` has no failure
          # return — so `false` from the liveness check is the only way out of the `with`.
          # An `{:error, _}` clause here matched nothing and only looked like a handled case.
          false -> {:error, :not_alive}
        end
    end
  end

  # :pg.join/3 is refcounted and :pg monitors the joined pid rather than this
  # directory, so memberships outlive a directory crash while `by_id` does not.
  # Reconciling after a restart would otherwise join every live agent a second time
  # and report a healthy process as two replicas.
  defp join_once(id, pid) do
    if pid in :pg.get_local_members(@scope, group(id)) do
      :ok
    else
      :pg.join(@scope, group(id), pid)
    end
  end

  defp drop_previous_monitor(id, pid, state) do
    case Map.get(state.by_id, id) do
      {^pid, old_ref} ->
        Process.demonitor(old_ref, [:flush])
        %{state | by_ref: Map.delete(state.by_ref, old_ref)}

      {_old_pid, old_ref} ->
        Process.demonitor(old_ref, [:flush])
        %{state | by_ref: Map.delete(state.by_ref, old_ref)}

      nil ->
        state
    end
  end
end
