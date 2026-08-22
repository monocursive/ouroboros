defmodule Ouroboros.Provider.Session.Jsonl do
  @moduledoc false

  # One JSONL process loop for every interactive dialect. Server-to-client requests
  # carry a method and an id; answers are a result on that same id. Routing on id
  # first would treat an approval as a reply to whatever we last sent.

  use GenServer, restart: :temporary

  require Logger

  alias Jido.Harness.{ApprovalResponse, Event, ProcessEvent, Protocol.JSONL, TurnRequest}

  def start_link({dialect, request, context}) when is_atom(dialect),
    do: GenServer.start_link(__MODULE__, {dialect, request, context})

  @impl true
  def init({dialect, request, context}) do
    with {:ok, executable, argv, env} <- dialect.command(request, context),
         {:ok, process_id} <-
           context.process_manager.start_owned_process(
             %{
               executable: executable,
               argv: argv,
               cwd: request.cwd,
               env: configured_env(context.config) |> Map.merge(env) |> Map.merge(request.env),
               env_mode: request.env_mode,
               stdin: true,
               pty: false,
               runtime_timeout_ms: :infinity,
               idle_timeout_ms: :infinity,
               metadata: %{
                 session_id: context.session_id,
                 provider: context.provider,
                 transport: dialect.name()
               }
             },
             context.owner
           ),
         {:ok, stream} <- context.process_manager.stream_process(process_id) do
      {:ok,
       %{
         dialect: dialect,
         request: request,
         context: context,
         owner: context.owner,
         provider: context.provider,
         process_id: process_id,
         stream: stream,
         reader: nil,
         buffer: "",
         next_id: 1,
         pending: %{},
         approvals: %{},
         provider_session_id: request.provider_session_id,
         provider_turn_id: nil,
         active_turn_id: nil,
         interrupted_turns: MapSet.new(),
         closing?: false
       }, {:continue, :start_reader}}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_continue(:start_reader, state) do
    parent = self()

    reader =
      Task.Supervisor.async_nolink(Jido.Harness.SessionTaskSupervisor, fn ->
        Enum.each(state.stream, &send(parent, {:session_jsonl, &1}))
      end)

    {:noreply, %{state | reader: reader}}
  end

  @impl true
  def handle_call({:initialize, request}, from, state) do
    case request(
           state,
           "initialize",
           state.dialect.initialize_params(request),
           {:initialize, from, request}
         ) do
      {:ok, state} -> {:noreply, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:send, _request, _turn_id}, _from, %{active_turn_id: id} = state)
      when not is_nil(id),
      do: {:reply, {:error, :busy}, state}

  def handle_call({:send, _request, _turn_id}, _from, %{provider_session_id: id} = state)
      when not is_binary(id),
      do: {:reply, {:error, :not_ready}, state}

  def handle_call({:send, %TurnRequest{} = turn, turn_id}, _from, state) do
    case state.dialect.start_turn(turn, turn_id, state) do
      {:request, method, params} ->
        case request(state, method, params, {:turn, turn_id}) do
          {:ok, state} -> {:reply, :ok, %{state | active_turn_id: turn_id}}
          {:error, reason} -> {:reply, {:error, reason}, state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:interrupt, requested}, _from, %{active_turn_id: turn_id} = state)
      when requested in [:active, turn_id] and not is_nil(turn_id) do
    state = %{state | interrupted_turns: MapSet.put(state.interrupted_turns, turn_id)}

    case dispatch_signal(state, state.dialect.interrupt(state), {:interrupt, turn_id}) do
      {:ok, state} -> {:reply, :ok, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:interrupt, _turn_id}, _from, state),
    do: {:reply, {:error, :not_active}, state}

  def handle_call({:respond_approval, {request_id, %ApprovalResponse{} = response}}, _from, state) do
    case Map.pop(state.approvals, request_id) do
      {nil, _approvals} ->
        {:reply, {:error, :unknown_request}, state}

      {%{id: id} = stash, approvals} ->
        reply =
          write(state, %{"id" => id, "result" => state.dialect.approval_reply(response, stash)})

        {:reply, reply, %{state | approvals: approvals}}
    end
  end

  def handle_call({:steer, request, request_id}, _from, state),
    do: {:reply, state.dialect.steer(state, request, request_id), state}

  def handle_call({:configure, changes}, _from, state),
    do: {:reply, state.dialect.configure(state, changes), state}

  def handle_call(:close, _from, state) do
    state = %{state | closing?: true}
    state = deny_pending_approvals(state)
    _ = dispatch_signal(state, state.dialect.close_signal(state), {:close, :active})

    if function_exported?(state.context.process_manager, :close_input, 1) do
      _ = state.context.process_manager.close_input(state.process_id)
    end

    _ = state.context.process_manager.cancel_process(state.process_id)
    if state.reader, do: Task.shutdown(state.reader, 5_000)
    {:stop, :normal, :ok, state}
  end

  @impl true
  def handle_info({:session_jsonl, %ProcessEvent{type: :stdout, data: data}}, state) do
    {records, buffer} = JSONL.push(state.buffer, data)
    state = Enum.reduce(records, %{state | buffer: buffer}, &handle_record/2)
    {:noreply, state}
  end

  def handle_info({:session_jsonl, %ProcessEvent{type: :stderr, data: data}}, state) do
    emit(state, :provider_event, %{
      "stream" => "stderr",
      "data" => data,
      "kind" => "#{state.dialect.name()}_log"
    })

    {:noreply, state}
  end

  def handle_info({:session_jsonl, %ProcessEvent{type: type, data: data}}, state)
      when type in [:failed, :timed_out] do
    state = fail_open_callers(state, {:process_failed, type, data})

    if state.active_turn_id do
      emit(state, :turn_failed, %{"error" => inspect(data || type)},
        turn_id: state.active_turn_id
      )
    end

    {:stop, {:process_failed, type}, state}
  end

  def handle_info({:session_jsonl, %ProcessEvent{type: type}}, state)
      when type in [:exited, :cancelled] do
    if state.closing? do
      {:noreply, state}
    else
      state = fail_open_callers(state, {:process_exited, type})

      if state.active_turn_id do
        emit(state, :turn_failed, %{"error" => "#{state.dialect.name()} #{type}"},
          turn_id: state.active_turn_id
        )
      end

      {:stop, {:process_exited, type}, state}
    end
  end

  def handle_info({ref, _result}, %{reader: %{ref: ref}} = state) do
    Process.demonitor(ref, [:flush])
    {:noreply, %{state | reader: nil}}
  end

  def handle_info({:DOWN, ref, :process, _pid, reason}, %{reader: %{ref: ref}} = state) do
    if state.closing?,
      do: {:noreply, %{state | reader: nil}},
      else: {:stop, {:reader_exit, reason}, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    _ = deny_pending_approvals(state)
    if state.process_id, do: state.context.process_manager.cancel_process(state.process_id)
    :ok
  rescue
    _ -> :ok
  end

  defp handle_record({:ok, %{"method" => method, "id" => id} = message}, state)
       when is_map_key(message, "id") do
    params = message["params"] || %{}

    case state.dialect.approval_request(method, params) do
      {:approval, payload, stash} ->
        request_id = to_string(id)

        emit(state, :approval_requested, payload,
          request_id: request_id,
          turn_id: state.active_turn_id
        )

        %{state | approvals: Map.put(state.approvals, request_id, Map.merge(stash, %{id: id}))}

      {:result, result} ->
        _ = write(state, %{"id" => id, "result" => result})
        state

      :method_not_found ->
        Logger.warning(
          "the #{state.dialect.name()} session requested #{inspect(method)}, which this dialect does not serve"
        )

        _ =
          write(state, %{
            "id" => id,
            "error" => %{
              "code" => -32601,
              "message" => state.dialect.unsupported_method_message()
            }
          })

        state
    end
  end

  defp handle_record({:ok, %{"id" => id} = message}, state)
       when not is_map_key(message, "method") do
    case Map.pop(state.pending, id) do
      {nil, _pending} ->
        emit(state, :provider_event, %{"kind" => "uncorrelated_response", "message" => message})
        state

      {pending, rest} ->
        complete_rpc(%{state | pending: rest}, pending, message)
    end
  end

  defp handle_record({:ok, %{"method" => method} = raw}, state) do
    params = raw["params"] || %{}
    apply_actions(state, state.dialect.handle_notification(method, params, raw, state))
  end

  defp handle_record({:ok, raw}, state) do
    emit(state, :provider_event, %{"kind" => "session_message", "message" => raw})
    state
  end

  defp handle_record({:error, line, reason}, state) do
    emit(state, :provider_event, %{
      "kind" => "decode_error",
      "line" => line,
      "error" => Exception.message(reason)
    })

    state
  end

  defp complete_rpc(state, {:initialize, from, request}, message) do
    case rpc_result(message) do
      {:ok, result} ->
        case state.dialect.after_initialize(result, request, state) do
          {:handshake, steps} -> run_handshake(state, from, steps)
          {:error, reason} -> reply_error(state, from, reason)
        end

      {:error, reason} ->
        reply_error(state, from, reason)
    end
  end

  defp complete_rpc(state, {:open, from}, message) do
    case rpc_result(message) do
      {:ok, result} ->
        session_id = state.dialect.session_id(result)

        if is_binary(session_id) do
          GenServer.reply(from, {:ok, session_id})
          %{state | provider_session_id: session_id}
        else
          reply_error(state, from, {:invalid_session_response, result})
        end

      {:error, reason} ->
        reply_error(state, from, reason)
    end
  end

  defp complete_rpc(state, pending, message) do
    apply_actions(state, state.dialect.handle_rpc(pending, message, state))
  end

  defp run_handshake(state, from, steps) do
    case Enum.reduce_while(steps, state, fn step, state ->
           case handshake_step(state, from, step) do
             {:ok, state} -> {:cont, state}
             {:error, reason} -> {:halt, {:error, state, reason}}
           end
         end) do
      {:error, state, reason} -> reply_error(state, from, reason)
      state -> state
    end
  end

  defp handshake_step(state, _from, {:notify, method, params}),
    do: case_write(state, %{"method" => method, "params" => params})

  defp handshake_step(state, from, {:open, method, params}),
    do: request(state, method, params, {:open, from})

  defp handshake_step(_state, _from, other), do: {:error, {:invalid_handshake_step, other}}

  defp case_write(state, message) do
    case write(state, message) do
      :ok -> {:ok, state}
      {:error, reason} -> {:error, reason}
    end
  end

  defp dispatch_signal(state, {:request, method, params}, tag),
    do: request(state, method, params, tag)

  defp dispatch_signal(state, {:notify, method, params}, _tag),
    do: case_write(state, %{"method" => method, "params" => params})

  defp dispatch_signal(state, :skip, _tag), do: {:ok, state}
  defp dispatch_signal(_state, {:error, reason}, _tag), do: {:error, reason}

  defp apply_actions(state, actions), do: Enum.reduce(actions, state, &apply_action/2)

  defp apply_action({:assign, fields}, state), do: Map.merge(state, fields)

  defp apply_action({:emit, type, payload, opts}, state) do
    emit(state, type, payload, opts)
    state
  end

  defp apply_action({:emit_event, event}, state) do
    emit_event(state, event)
    state
  end

  defp deny_pending_approvals(state) do
    Enum.each(state.approvals, fn {_request_id, %{id: id} = stash} ->
      _ = write(state, %{"id" => id, "result" => state.dialect.deny_reply(stash)})
    end)

    %{state | approvals: %{}}
  end

  defp request(state, method, params, pending_value) do
    id = state.next_id
    message = %{"id" => id, "method" => method, "params" => params}

    case write(state, message) do
      :ok -> {:ok, %{state | next_id: id + 1, pending: Map.put(state.pending, id, pending_value)}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp rpc_result(%{"error" => error}), do: {:error, error}
  defp rpc_result(%{"result" => result}), do: {:ok, result || %{}}
  defp rpc_result(message), do: {:error, {:invalid_rpc_response, message}}

  defp reply_error(state, from, reason) do
    GenServer.reply(from, {:error, reason})
    state
  end

  defp fail_open_callers(state, reason) do
    Enum.each(state.pending, fn
      {_id, {:initialize, from, _request}} -> GenServer.reply(from, {:error, reason})
      {_id, {:open, from}} -> GenServer.reply(from, {:error, reason})
      _other -> :ok
    end)

    %{state | pending: %{}}
  end

  defp emit_event(state, event) do
    event = %{
      event
      | provider: state.provider,
        provider_session_id: state.provider_session_id,
        turn_id: event.turn_id || state.active_turn_id
    }

    Jido.Harness.SessionAdapter.emit(state.owner, event)
  end

  defp emit(state, type, payload, options \\ []) do
    Jido.Harness.SessionAdapter.emit(
      state.owner,
      Event.new!(
        type: type,
        provider: state.provider,
        provider_session_id: state.provider_session_id,
        turn_id: Keyword.get(options, :turn_id) || state.active_turn_id,
        request_id: Keyword.get(options, :request_id),
        payload: payload
      )
    )
  end

  defp write(state, value),
    do:
      state.context.process_manager.send_input(
        state.process_id,
        JSONL.encode(state.dialect.envelope(value))
      )

  defp configured_env(config) do
    config[:env] || config["env"] || %{}
  end
end
