defmodule Ouroboros.Provider.Native.Run do
  @moduledoc false

  use GenServer, restart: :temporary

  alias Jido.Harness.ApprovalResponse
  alias Jido.Harness.Event
  alias Jido.Harness.SessionRequest
  alias Jido.Harness.TurnRequest
  alias Ouroboros.Provider.Native.Session

  @registry Ouroboros.Provider.Native.Registry
  @launch_timeout 35_000

  def start(request, context) do
    spec = {__MODULE__, {request, context}}

    case DynamicSupervisor.start_child(Jido.Harness.SessionTransportSupervisor, spec) do
      {:ok, pid} ->
        case GenServer.call(pid, :launch, @launch_timeout) do
          {:ok, provider_session_id} ->
            {:ok, pid, provider_session_id}

          {:error, _reason} = error ->
            _ = stop(pid)
            error
        end

      {:error, _reason} = error ->
        error
    end
  end

  def stream(pid) when is_pid(pid) do
    Stream.resource(
      fn -> pid end,
      fn pid ->
        case GenServer.call(pid, :next, :infinity) do
          {:event, %Event{} = event} -> {[event], pid}
          :halt -> {:halt, pid}
        end
      end,
      &stop/1
    )
  end

  def respond(run_id, request_id, %ApprovalResponse{} = response) when is_binary(run_id) do
    case lookup(run_id) do
      nil -> {:error, :run_not_active}
      pid -> GenServer.call(pid, {:respond_approval, request_id, response})
    end
  catch
    :exit, reason -> {:error, {:run_transport_exit, reason}}
  end

  def stop(pid) when is_pid(pid) do
    DynamicSupervisor.terminate_child(Jido.Harness.SessionTransportSupervisor, pid)
  catch
    :exit, _reason -> :ok
  end

  def child_spec(arg) do
    %{
      id: {__MODULE__, make_ref()},
      start: {__MODULE__, :start_link, [arg]},
      restart: :temporary
    }
  end

  def start_link(arg), do: GenServer.start_link(__MODULE__, arg)

  @impl true
  def init({request, context}) do
    {:ok,
     %{
       request: request,
       context: context,
       handle: nil,
       provider_session_id: nil,
       queue: :queue.new(),
       waiter: nil,
       terminal?: false
     }}
  end

  @impl true
  def handle_call(:launch, _from, state) do
    with :ok <- register(state.context.run_id),
         {:ok, session_request} <- session_request(state.request),
         {:ok, handle} <- Session.open(session_request, session_context(state.context)) do
      turn_id = "turn_" <> random(9)

      case Session.send(handle, turn_request(state.request), turn_id) do
        :ok ->
          provider_session_id = session_request.provider_session_id || session_provider_id(handle)

          {:reply, {:ok, provider_session_id},
           %{state | handle: handle, provider_session_id: provider_session_id}}

        {:error, reason} ->
          _ = Session.close(handle)
          {:stop, reason, {:error, reason}, state}
      end
    else
      {:error, reason} -> {:stop, reason, {:error, reason}, state}
    end
  end

  def handle_call(:next, from, %{queue: queue} = state) do
    case :queue.out(queue) do
      {{:value, event}, queue} ->
        {:reply, {:event, event}, %{state | queue: queue}}

      {:empty, _queue} when state.terminal? ->
        {:reply, :halt, state}

      {:empty, _queue} ->
        {:noreply, %{state | waiter: from}}
    end
  end

  def handle_call({:respond_approval, request_id, response}, _from, %{handle: handle} = state)
      when is_pid(handle) do
    {:reply, Session.respond_approval(handle, request_id, response), state}
  end

  def handle_call({:respond_approval, _request_id, _response}, _from, state) do
    {:reply, {:error, :run_not_ready}, state}
  end

  @impl true
  def handle_info({:session_adapter_event, %Event{} = event}, state) do
    if ready_event?(event) do
      {:noreply, state}
    else
      terminal? =
        state.terminal? or event.type in [:turn_completed, :turn_failed, :turn_interrupted]

      case state.waiter do
        nil ->
          {:noreply, %{state | queue: :queue.in(event, state.queue), terminal?: terminal?}}

        waiter ->
          GenServer.reply(waiter, {:event, event})
          {:noreply, %{state | waiter: nil, terminal?: terminal?}}
      end
    end
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    if is_pid(state.handle), do: Session.close(state.handle)
    :ok
  rescue
    _error -> :ok
  end

  defp session_request(request) do
    provider_options =
      request.provider_options
      |> Map.new()
      |> Map.put_new("max_iterations", request.max_turns)
      |> Map.reject(fn {_key, value} -> is_nil(value) end)

    SessionRequest.new(%{
      provider: request.provider,
      cwd: request.cwd,
      model: request.model,
      provider_session_id: request.provider_session_id,
      system_prompt: request.system_prompt,
      allowed_tools: request.allowed_tools,
      disallowed_tools: request.disallowed_tools,
      add_dirs: request.add_dirs,
      mcp_config: request.mcp_config,
      approval_mode: request.approval_mode,
      sandbox_mode: request.sandbox_mode,
      reasoning_effort: request.reasoning_effort,
      env: request.env,
      env_mode: request.env_mode,
      metadata: request.metadata,
      provider_options: provider_options,
      turn_runtime_timeout_ms: request.runtime_timeout_ms,
      turn_idle_timeout_ms: request.idle_timeout_ms,
      approval_timeout_ms:
        Application.get_env(:ouroboros, :coding_approval_timeout_ms, 5 * 60 * 1_000)
    })
  end

  defp turn_request(request) do
    TurnRequest.new!(%{
      prompt: request.prompt,
      attachments: request.attachments,
      reasoning_effort: request.reasoning_effort
    })
  end

  defp session_context(context) do
    %{
      session_id: context.run_id,
      provider: context.provider,
      owner: self(),
      adapter: Ouroboros.Provider.Native,
      config: context.config,
      process_manager: context.process_manager,
      telemetry_context: context.telemetry_context
    }
  end

  defp register(run_id) do
    case Registry.register(@registry, {:run, run_id}, nil) do
      {:ok, _owner} -> :ok
      {:error, {:already_registered, _pid}} -> {:error, :run_already_active}
    end
  rescue
    ArgumentError -> {:error, :native_registry_unavailable}
  end

  defp lookup(run_id) do
    case Registry.lookup(@registry, {:run, run_id}) do
      [{pid, _value}] -> pid
      [] -> nil
    end
  rescue
    ArgumentError -> nil
  end

  defp ready_event?(%Event{type: :provider_event, payload: %{"kind" => "native_ready"}}), do: true
  defp ready_event?(_event), do: false

  defp session_provider_id(handle) do
    case Session.info(handle) do
      {:ok, %{provider_session_id: id}} -> id
      {:ok, %{"provider_session_id" => id}} -> id
      _other -> nil
    end
  end

  defp random(bytes), do: :crypto.strong_rand_bytes(bytes) |> Base.url_encode64(padding: false)
end
