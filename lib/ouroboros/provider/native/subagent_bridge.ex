defmodule Ouroboros.Provider.Native.SubagentBridge do
  @moduledoc """
  Session-bound access to the native child tool path, for a caller outside this runtime.

  `ouro mcp-serve` is the one such caller: an MCP client bound to one session by its
  environment reaches `subagent.spawn` / `subagent.result` / `subagent.stop` through the
  gateway, and they land here. The coordinator supplies the current request; gateway
  arguments never supply a principal, workspace authority, tool allowlist or approval mode.
  The child runs on the owner's own live transport — there is one provider and it holds its
  session in this VM, so there is nothing to open a sidecar for.

  Calls are serialized while the coordinator remains free to handle approvals. Foreground
  approval relays are cancelled when their Loop, dispatch or owner ends. Up to 128
  spawn receipts are retained for the owner's lifetime, with no eviction: forgetting one
  would let an ambiguous transport retry launch another child. Further spawns are refused
  once full. Result/stop receipts have a separate bounded cache, so collecting and stopping
  children remain available. An evicted result retry can report already collected; it can
  never create work.
  """
  use GenServer, restart: :temporary
  alias Ouroboros.Interactive.Task, as: Owner
  alias Ouroboros.Provider.Native.Session
  alias Ouroboros.Session.ApprovalResponse

  @limit 128
  @timeout 15 * 60_000
  @registry Ouroboros.Interactive.Registry

  def call(id, request_id, name, input) do
    with owner when is_pid(owner) <- Owner.whereis(id),
         {:ok, bridge} <- ensure(owner, id) do
      GenServer.call(bridge, {:tool, request_id, name, input}, @timeout)
    else
      nil -> {:error, :not_found}
      other -> other
    end
  catch
    :exit, reason -> {:error, {:bridge_unavailable, reason}}
  end

  def close(owner) do
    case Registry.lookup(@registry, {__MODULE__, owner}) do
      [{pid, _}] -> GenServer.cast(pid, :close)
      [] -> :ok
    end
  end

  defp ensure(owner, id) do
    case DynamicSupervisor.start_child(
           Ouroboros.Interactive.TaskSupervisor,
           {__MODULE__, {owner, id}}
         ) do
      {:error, {:already_started, pid}} -> {:ok, pid}
      result -> result
    end
  end

  def start_link({owner, id}),
    do:
      GenServer.start_link(__MODULE__, {owner, id},
        name: {:via, Registry, {@registry, {__MODULE__, owner}}}
      )

  @impl true
  def init({owner, id}) do
    Process.flag(:trap_exit, true)

    {:ok,
     %{
       owner: owner,
       id: id,
       monitor: Process.monitor(owner),
       session: nil,
       task: nil,
       cache: %{},
       relays: %{}
     }}
  end

  @impl true
  def handle_call({:tool, request_id, name, input}, from, state) do
    key = {name, :crypto.hash(:sha256, :erlang.term_to_binary(input))}

    cond do
      not is_binary(request_id) or byte_size(request_id) not in 1..128 ->
        {:reply, {:error, :invalid_request_id}, state}

      name not in ["agent", "agent_result", "fleet"] or not is_map(input) ->
        {:reply, {:error, :invalid_bridge_tool}, state}

      Map.has_key?(state.cache, request_id) ->
        case state.cache[request_id] do
          {^key, reply} -> {:reply, reply, state}
          _ -> {:reply, {:error, :request_id_conflict}, state}
        end

      state.task != nil ->
        if state.task.id == request_id and state.task.key == key do
          if length(state.task.waiters) < 8,
            do: {:noreply, put_in(state.task.waiters, [from | state.task.waiters])},
            else: {:reply, {:error, :busy}, state}
        else
          {:reply, {:error, :busy}, state}
        end

      name == "agent" and receipt_count(state.cache, "agent") >= @limit ->
        # Never evict a spawn receipt and silently turn a transport retry into another child.
        {:reply, {:error, :bridge_request_capacity}, state}

      true ->
        state = %{state | cache: trim_results(state.cache, name)}
        parent = self()

        task =
          Task.Supervisor.async_nolink(Ouroboros.SessionTaskSupervisor, fn ->
            run(parent, state, request_id, name, input)
          end)

        {:noreply,
         %{
           state
           | task: %{ref: task.ref, pid: task.pid, id: request_id, key: key, waiters: [from]}
         }}
    end
  end

  # A sidecar is recorded before dispatch can create a child, so owner termination always closes it.
  def handle_call({:session, session}, _from, state),
    do: {:reply, :ok, %{state | session: session}}

  # The Loop emit callback must return immediately so its deadline and interrupt receive
  # remain live. Relay callers are owned here and die when that dispatch or Loop ends.
  def handle_call({:relay_approval, event}, {loop, _}, state) do
    if state.task == nil or map_size(state.relays) >= 8 do
      deny_relay(loop, event.request_id)
      {:reply, :ok, state}
    else
      task =
        Task.Supervisor.async_nolink(Ouroboros.SessionTaskSupervisor, fn ->
          response = Ouroboros.InteractiveSession.relay_approval(state.id, event.payload)
          send(loop, {:native_approval, event.request_id, response})
          :ok
        end)

      relay = %{
        task: task,
        loop: loop,
        monitor: Process.monitor(loop),
        request_id: event.request_id
      }

      {:reply, :ok, %{state | relays: Map.put(state.relays, task.ref, relay)}}
    end
  end

  @impl true
  def handle_info({ref, reply}, %{task: %{ref: ref} = task} = state) do
    Process.demonitor(ref, [:flush])
    state = cancel_relays(state)
    Enum.each(task.waiters, &GenServer.reply(&1, reply))
    {:noreply, %{state | task: nil, cache: Map.put(state.cache, task.id, {task.key, reply})}}
  end

  def handle_info({:DOWN, ref, :process, _pid, _reason}, %{monitor: ref} = state),
    do: {:stop, :normal, state}

  def handle_info({:DOWN, ref, :process, _pid, reason}, %{task: %{ref: ref} = task} = state) do
    reply = {:error, {:bridge_dispatch_failed, reason}}
    state = cancel_relays(state)
    Enum.each(task.waiters, &GenServer.reply(&1, reply))
    {:noreply, %{state | task: nil, cache: Map.put(state.cache, task.id, {task.key, reply})}}
  end

  def handle_info({ref, _reply}, state) when is_map_key(state.relays, ref) do
    {relay, relays} = Map.pop(state.relays, ref)
    Process.demonitor(ref, [:flush])
    Process.demonitor(relay.monitor, [:flush])
    {:noreply, %{state | relays: relays}}
  end

  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    case Map.pop(state.relays, ref) do
      {nil, _} ->
        case Enum.find(state.relays, fn {_key, relay} -> relay.monitor == ref end) do
          {key, relay} ->
            Task.shutdown(relay.task, :brutal_kill)
            {:noreply, %{state | relays: Map.delete(state.relays, key)}}

          nil ->
            {:noreply, state}
        end

      {relay, relays} ->
        Process.demonitor(relay.monitor, [:flush])
        deny_relay(relay.loop, relay.request_id)
        {:noreply, %{state | relays: relays}}
    end
  end

  def handle_info(_message, state), do: {:noreply, state}
  @impl true
  def handle_cast(:close, state), do: {:stop, :normal, state}

  @impl true
  def terminate(_reason, state) do
    cancel_relays(state)
    if state.task, do: Process.exit(state.task.pid, :kill)
    :ok
  end

  defp cancel_relays(state) do
    Enum.each(state.relays, fn {_ref, relay} ->
      Process.demonitor(relay.monitor, [:flush])
      Task.shutdown(relay.task, :brutal_kill)
    end)

    %{state | relays: %{}}
  end

  defp deny_relay(loop, request_id) do
    response =
      ApprovalResponse.new!(%{decision: :deny, scope: :once, reason: "Approval relay stopped"})

    send(loop, {:native_approval, request_id, response})
  end

  defp receipt_count(cache, name),
    do: Enum.count(cache, fn {_id, {{tool, _digest}, _reply}} -> tool == name end)

  defp trim_results(cache, "agent"), do: cache

  defp trim_results(cache, _name) do
    if receipt_count(cache, "agent_result") >= @limit do
      {id, _} = Enum.find(cache, fn {_id, {{tool, _}, _}} -> tool == "agent_result" end)
      Map.delete(cache, id)
    else
      cache
    end
  end

  defp run(bridge, state, request_id, name, input) do
    with {:ok, snapshot} <- GenServer.call(state.owner, :subagent_bridge_state),
         {:ok, session} <- transport(bridge, state, snapshot) do
      emit = fn event ->
        if event.type == :approval_requested do
          GenServer.call(bridge, {:relay_approval, event})
        else
          GenServer.cast(state.owner, {:subagent_bridge_event, event})
        end
      end

      Session.bridge_tool(session, %{id: request_id, name: name, input: input}, emit)
    end
  end

  defp transport(_bridge, %{session: session}, _snapshot) when is_pid(session),
    do: {:ok, session}

  # The owner's own live transport, and nothing else: one provider, one session, held in
  # this VM. A session that has not opened one has nothing to run a child on, and says so.
  defp transport(bridge, _state, %{provider_session_id: id}) do
    case Session.whereis(id) do
      nil ->
        {:error, :no_live_transport}

      session ->
        :ok = GenServer.call(bridge, {:session, session})
        {:ok, session}
    end
  end
end
