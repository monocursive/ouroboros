defmodule Ouroboros.Provider.Native.Exec.Registry do
  @moduledoc false

  use GenServer

  alias Ouroboros.Provider.Native.ProcessSignal

  @grace_ms 500

  def start_link(opts \\ []),
    do: GenServer.start_link(__MODULE__, %{}, name: Keyword.get(opts, :name, __MODULE__))

  def register(owner, os_pid), do: GenServer.call(__MODULE__, {:register, owner, os_pid})
  def unregister(owner, os_pid), do: GenServer.call(__MODULE__, {:unregister, owner, os_pid})
  def cancel(owner), do: GenServer.call(__MODULE__, {:cancel, owner}, 2_000)

  @impl true
  def init(state), do: {:ok, state}

  @impl true
  def handle_call({:register, owner, os_pid}, _from, state) do
    state =
      case Map.get(state, owner) do
        {_old_pid, old_ref} ->
          Process.demonitor(old_ref, [:flush])
          Map.delete(state, owner)

        nil ->
          state
      end

    ref = Process.monitor(owner)
    {:reply, :ok, Map.put(state, owner, {os_pid, ref})}
  end

  def handle_call({:unregister, owner, os_pid}, _from, state) do
    case Map.get(state, owner) do
      {^os_pid, ref} ->
        Process.demonitor(ref, [:flush])
        {:reply, :ok, Map.delete(state, owner)}

      _ ->
        {:reply, :ok, state}
    end
  end

  def handle_call({:cancel, owner}, _from, state) do
    case Map.get(state, owner) do
      {os_pid, _ref} ->
        _ = ProcessSignal.signal(os_pid, :sigterm)
        wait_dead(os_pid, System.monotonic_time(:millisecond) + @grace_ms)
        {:reply, :ok, state}

      nil ->
        {:reply, :not_running, state}
    end
  end

  @impl true
  def handle_info({:DOWN, ref, :process, owner, _reason}, state) do
    case Map.get(state, owner) do
      {os_pid, ^ref} ->
        # Registration is removed in this same mailbox turn before any later owner can reuse
        # it. The OS identity is still numeric, so this is an immediate best-effort fence,
        # not a cross-platform proof against PID reuse after an unobserved leader exit.
        _ = ProcessSignal.signal(os_pid, :sigkill)
        {:noreply, Map.delete(state, owner)}

      _ ->
        {:noreply, state}
    end
  end

  defp wait_dead(os_pid, deadline) do
    if ProcessSignal.alive?(os_pid) and System.monotonic_time(:millisecond) < deadline do
      Process.sleep(20)
      wait_dead(os_pid, deadline)
    else
      if ProcessSignal.alive?(os_pid), do: ProcessSignal.signal(os_pid, :sigkill)
      :ok
    end
  end
end
