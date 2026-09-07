defmodule Ouroboros.Provider.Native.SubagentBridge do
  @moduledoc """
  Session-bound vendor access to the native child tool path.

  The coordinator supplies the current request; gateway arguments never supply a principal,
  workspace authority, tool allowlist or approval mode. Native sessions reuse their live
  transport. Other providers get a native sidecar using this node's configured native model,
  since vendor aliases such as `sonnet` are not portable model specifications.

  Calls are serialized while the coordinator remains free to handle approvals. Up to 128
  spawn receipts are retained for the owner's lifetime, with no eviction: forgetting one
  would let an ambiguous transport retry launch another child. Further spawns are refused
  once full. Result/stop receipts have a separate bounded cache, so collecting and stopping
  children remain available. An evicted result retry can report already collected; it can
  never create work. Closing or losing the owner closes its sidecar.
  """
  use GenServer, restart: :temporary
  alias Ouroboros.Interactive.Task, as: Owner
  alias Ouroboros.Provider.Native.{Loop, Session, Tools}
  alias Jido.Harness.SessionRequest

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
       model: nil,
       owned?: false,
       task: nil,
       cache: %{}
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
          Task.Supervisor.async_nolink(Jido.Harness.SessionTaskSupervisor, fn ->
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
  def handle_call({:session, session, owned?, model}, _from, state),
    do: {:reply, :ok, %{state | session: session, owned?: owned?, model: model}}

  @impl true
  def handle_info({ref, reply}, %{task: %{ref: ref} = task} = state) do
    Process.demonitor(ref, [:flush])
    Enum.each(task.waiters, &GenServer.reply(&1, reply))
    {:noreply, %{state | task: nil, cache: Map.put(state.cache, task.id, {task.key, reply})}}
  end

  def handle_info({:DOWN, ref, :process, _pid, _reason}, %{monitor: ref} = state),
    do: {:stop, :normal, state}

  def handle_info({:DOWN, ref, :process, _pid, reason}, %{task: %{ref: ref} = task} = state) do
    reply = {:error, {:bridge_dispatch_failed, reason}}
    Enum.each(task.waiters, &GenServer.reply(&1, reply))
    {:noreply, %{state | task: nil, cache: Map.put(state.cache, task.id, {task.key, reply})}}
  end

  def handle_info({:session_adapter_event, %{type: :provider_event} = event}, state) do
    if event.payload["kind"] == "subagent",
      do: GenServer.cast(state.owner, {:subagent_bridge_event, event})

    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}
  @impl true
  def handle_cast(:close, state), do: {:stop, :normal, state}

  @impl true
  def terminate(_reason, state) do
    if state.task, do: Process.exit(state.task.pid, :kill)
    if state.owned? and is_pid(state.session), do: Session.close(state.session)
    :ok
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
    model = if name == "agent_result", do: state.model

    with {:ok, snapshot} <- GenServer.call(state.owner, :subagent_bridge_state),
         {:ok, request} <- native_request(snapshot, model),
         {:ok, session, owned?} <- transport(bridge, state, snapshot, request) do
      emit = fn event ->
        if event.type == :approval_requested do
          response = Ouroboros.InteractiveSession.relay_approval(state.id, event.payload)
          send(self(), {:native_approval, event.request_id, response})
        else
          GenServer.cast(state.owner, {:subagent_bridge_event, event})
        end
      end

      Session.bridge_tool(
        session,
        if(owned?, do: request),
        %{id: request_id, name: name, input: input},
        emit
      )
    end
  end

  defp transport(_bridge, %{session: session, owned?: owned?}, _snapshot, _request)
       when is_pid(session),
       do: {:ok, session, owned?}

  defp transport(bridge, _state, %{provider: :native, provider_session_id: id}, _request) do
    case Session.whereis(id) do
      nil ->
        {:error, :no_live_transport}

      session ->
        :ok = GenServer.call(bridge, {:session, session, false, nil})
        {:ok, session, false}
    end
  end

  defp transport(bridge, _state, snapshot, request) do
    context = %{
      session_id: snapshot.principal_id,
      provider: :native,
      owner: bridge,
      adapter: Session,
      config: %{},
      process_manager: Jido.Harness.ProcessManager,
      telemetry_context: %{}
    }

    with {:ok, session} <- Session.open(request, context) do
      :ok = GenServer.call(bridge, {:session, session, true, request.model})
      {:ok, session, true}
    end
  end

  @doc false
  def native_request(snapshot), do: native_request(snapshot, nil)

  defp native_request(%{request: request, provider: provider}, fallback_model) do
    if provider == :native do
      {:ok, nil}
    else
      # Vendor model aliases are not ReqLLM specs. Resolve the node's native default explicitly.
      with {:ok, model} <- Loop.resolve_model(fallback_model) do
        allowed = translate_tools(request[:allowed_tools], :allow)
        disallowed = translate_tools(request[:disallowed_tools], :deny)

        attrs =
          request
          |> Map.drop([:transport, :provider_session_id, :mcp_config, :reasoning_effort])
          |> Map.merge(%{
            provider: :native,
            model: model,
            allowed_tools: allowed,
            disallowed_tools: disallowed,
            provider_options: Map.take(request[:provider_options] || %{}, [:plan, "plan"]),
            env: %{},
            env_mode: :overlay
          })

        SessionRequest.new(attrs)
      end
    end
  end

  defp translate_tools(names, :allow) when names in [nil, []],
    do:
      ~w(read write edit bash grep glob ls web_fetch code_intel ask_user agent agent_result fleet plan)

  defp translate_tools(names, :deny) when names in [nil, []], do: []

  defp translate_tools(names, mode) do
    known = MapSet.new(Enum.map(Tools.modules(), & &1.name()))

    Enum.flat_map(names, fn name ->
      candidate = name |> String.replace_prefix("mcp__ouroboros__", "") |> String.downcase()

      candidate =
        if mode == :deny, do: candidate |> String.split("(", parts: 2) |> hd(), else: candidate

      candidate =
        case candidate do
          "task" -> "agent"
          "multiedit" -> "edit"
          "notebookedit" -> "write"
          "webfetch" -> "web_fetch"
          "todowrite" -> "plan"
          other -> other
        end

      cond do
        MapSet.member?(known, candidate) ->
          [candidate]

        mode == :deny and String.contains?(candidate, "*") ->
          # Pattern syntax is vendor-owned. A pattern deny narrows the entire native tool set.
          MapSet.to_list(known)

        true ->
          ["unavailable_vendor_tool:" <> name]
      end
    end)
  end
end
