defmodule Ouroboros.Provider.Session.Jsonl do
  @moduledoc false

  # One JSONL process loop for every interactive dialect. Server-to-client requests
  # carry a method and an id; answers are a result on that same id. Routing on id
  # first would treat an approval as a reply to whatever we last sent.

  use GenServer, restart: :temporary

  require Logger

  alias Jido.Harness.{ApprovalResponse, Event, ProcessEvent, Protocol.JSONL, TurnRequest}
  alias Ouroboros.Control.Permissions.Seam
  alias Ouroboros.Provider.Session.Service

  @registry Ouroboros.Provider.Session.Registry

  def start_link({dialect, request, context}) when is_atom(dialect),
    do: GenServer.start_link(__MODULE__, {dialect, request, context})

  @doc """
  The transport process serving one harness session on this node, or `nil`.

  Every JSONL transport registers itself in `Ouroboros.Provider.Session.Registry` when it
  starts, keyed by the harness session id. That registry is the only route a runtime verb
  has to the wire: `Jido.Harness.Session` exposes the session *worker* but never the
  transport handle underneath it, and the three verbs that have to reach a dialect
  directly — a Codex compaction, a live `model/list`, an ACP `session/set_mode` — are
  exactly the ones the pinned harness has no vocabulary for.

  Its own `Jido.Harness.SessionRegistry` is deliberately not borrowed for this, however
  distinct the key: `Jido.Harness.SessionManager.list/1` selects **every** key in that
  registry and calls each pid as though it were a session worker, so one extra
  registration there turns every session listing into a crash.
  """
  @spec whereis(String.t()) :: pid() | nil
  def whereis(session_id) when is_binary(session_id) do
    case Registry.lookup(@registry, {:ouroboros_transport, session_id}) do
      [{pid, _value} | _rest] -> pid
      [] -> nil
    end
  end

  def whereis(_session_id), do: nil

  @doc """
  Every live JSONL transport on this node, as `{session_id, pid, %{dialect:, provider:}}`.

  Bounded by the number of interactive sessions this node is running, and read rather
  than called: nothing here asks a transport process a question, so a busy session cannot
  slow down a listing.
  """
  @spec transports() :: [{String.t(), pid(), map()}]
  def transports do
    Registry.select(@registry, [
      {{{:ouroboros_transport, :"$1"}, :"$2", :"$3"}, [], [{{:"$1", :"$2", :"$3"}}]}
    ])
  end

  @doc """
  Asks the dialect for one correlated round trip and waits for the provider's answer.

  The three verbs the pinned harness cannot carry go through here. `{:error, :unsupported}`
  is a dialect saying its protocol has no such frame, and it is a refusal by declaration:
  `Ouroboros.Provider` answers the same question from the same dialect before a caller
  ever reaches this.
  """
  @spec ask(pid(), atom(), map(), timeout()) :: {:ok, term()} | {:error, term()}
  def ask(pid, verb, args \\ %{}, timeout \\ 30_000) when is_pid(pid) and is_atom(verb) do
    GenServer.call(pid, {:ask, verb, args}, timeout)
  catch
    :exit, reason -> {:error, {:transport_call_exit, reason}}
  end

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
      _ = register(context, dialect)

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
         available_modes: [],
         services: Service.new(),
         closing?: false
       }, {:continue, :start_reader}}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  # Best-effort on purpose. A registry that refuses the key — a duplicate session id, a
  # registry not started in a bare unit test — costs the three runtime verbs that look a
  # transport up, and must not cost the session itself.
  defp register(context, dialect) do
    case Map.get(context, :session_id) do
      session_id when is_binary(session_id) ->
        Registry.register(@registry, {:ouroboros_transport, session_id}, %{
          dialect: dialect,
          provider: Map.get(context, :provider)
        })

      _unnamed ->
        :ok
    end
  rescue
    _error -> :ok
  catch
    _kind, _reason -> :ok
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

      # C4. A service approval is a human answering a request the agent made of *this
      # runtime*, so the answer is the work: an approve performs the write or starts the
      # terminal and answers with its result, and a deny answers with an error rather than
      # an empty success an agent would read as "done".
      {%{service: _fields, id: id} = stash, approvals} ->
        {:reply, reply, services, actions} =
          Service.resume(state.services, stash, response, service_context(state, id))

        state = apply_actions(%{state | services: services, approvals: approvals}, actions)
        _ = write_service_reply(state, id, reply)
        _ = Seam.answered(state.dialect.name(), Seam.decision_id(request_id), stash, response)
        {:reply, :ok, state}

      {%{id: id} = stash, approvals} ->
        reply =
          write(state, %{"id" => id, "result" => state.dialect.approval_reply(response, stash)})

        # The human's answer joins the rule decisions in the ledger, and a session-scoped
        # one becomes the rule that stops the next identical question (C1/I1). Best-effort
        # on purpose: the answer has already reached the provider, and a failed audit
        # write must not turn a delivered approval into an error the caller retries.
        _ = Seam.answered(state.dialect.name(), Seam.decision_id(request_id), stash, response)

        {:reply, reply, %{state | approvals: approvals}}
    end
  end

  # A dialect that answers `{:request, …}` is steering over a correlated JSON-RPC call, so
  # the id has to come from this process's counter and be recorded in `pending` — the
  # dialect cannot do either, because the state it was handed is discarded on reply. That
  # is why the frame comes back here rather than being written there: an id spent behind
  # this process's back would be reused by the next `turn/start`.
  def handle_call({:steer, request, request_id}, _from, state) do
    case state.dialect.steer(state, request, request_id) do
      {:request, method, params} ->
        case request(state, method, params, {:steer, request_id}) do
          {:ok, state} -> {:reply, :ok, state}
          {:error, reason} -> {:reply, {:error, reason}, state}
        end

      other ->
        {:reply, other, state}
    end
  end

  # A dialect that accepts a change is stating that the *request* it builds turns from
  # here on, so the runtime's own copy of the request has to move with it — the Harness
  # worker updates its copy, and this process is the one that renders the next turn.
  # A dialect that refuses leaves both untouched.
  def handle_call({:configure, changes}, _from, state) do
    case state.dialect.configure(state, changes) do
      :ok -> {:reply, :ok, %{state | request: configured_request(state.request, changes)}}
      {:error, reason} -> {:reply, {:error, reason}, state}
      other -> {:reply, {:error, {:invalid_dialect_configure_result, other}}, state}
    end
  end

  # C4. The dialect builds the frame; this process spends the id and correlates the
  # answer, exactly as `{:steer, …}` does and for the same reason. The caller waits,
  # because every one of these verbs is a question whose answer is the point.
  def handle_call({:ask, verb, args}, from, state) do
    case state.dialect.ask(verb, args, state) do
      {:request, method, params} ->
        case request(state, method, params, {:ask, verb, from}) do
          {:ok, state} -> {:noreply, state}
          {:error, reason} -> {:reply, {:error, reason}, state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}

      other ->
        {:reply, {:error, {:invalid_dialect_ask_result, other}}, state}
    end
  end

  def handle_call(:close, _from, state) do
    state = %{state | closing?: true}
    state = deny_pending_approvals(state)
    state = release_services(state)
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

  # C4's terminals are ports this process owns, so their output and their exits arrive
  # here as ordinary messages. Offered to the services first and left alone otherwise, so
  # a session that never asked for a terminal — every non-ACP session — is unchanged.
  def handle_info(message, state) do
    case Service.handle_message(state.services, message) do
      {:ok, services, actions} ->
        {:noreply, apply_actions(%{state | services: services}, actions)}

      :not_mine ->
        {:noreply, state}
    end
  end

  @impl true
  def terminate(_reason, state) do
    _ = deny_pending_approvals(state)
    _ = release_services(state)
    # "Don't ask again for this session" ends when the session does. Forgetting them on a
    # provider restart the operator did not ask for costs one repeated prompt; keeping
    # them would let an answer outlive the conversation that produced it, and would leave
    # the rule store growing with every session this node ever ran.
    _ = Seam.forget_session()
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
        serve_request(state, method, params, id)
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

  # C4. The second inbound seam, tried only after the approval one has said this is not
  # its method. A dialect that serves nothing answers `:method_not_found` here too and the
  # frame gets the same `-32601` it always got.
  defp serve_request(state, method, params, id) do
    case state.dialect.service_request(method, params, state) do
      {:service, operation, args} ->
        run_service(state, operation, args, id)

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

  defp run_service(state, operation, args, id) do
    case Service.serve(state.services, operation, args, service_context(state, id)) do
      {:reply, reply, services, actions} ->
        state = apply_actions(%{state | services: services}, actions)
        _ = write_service_reply(state, id, reply)
        state

      # A service the permission engine left to a person becomes the same
      # `approval_requested` a provider's own request does, so one approval channel serves
      # both and A8's modal has nothing new to learn.
      {:approval, payload, stash, services} ->
        request_id = to_string(id)

        emit(state, :approval_requested, payload,
          request_id: request_id,
          turn_id: state.active_turn_id
        )

        %{
          state
          | services: services,
            approvals: Map.put(state.approvals, request_id, Map.put(stash, :id, id))
        }

      {:defer, services, actions} ->
        apply_actions(%{state | services: services}, actions)
    end
  end

  defp service_context(state, id) do
    %{
      root: state.request.cwd,
      sandbox_mode: Map.get(state.request, :sandbox_mode),
      turn_id: state.active_turn_id,
      rpc_id: id
    }
  end

  defp write_service_reply(state, id, {:result, result}),
    do: write(state, %{"id" => id, "result" => result})

  defp write_service_reply(state, id, {:error, code, message, data}) do
    error = %{"code" => code, "message" => message}
    error = if data == %{}, do: error, else: Map.put(error, "data", data)
    write(state, %{"id" => id, "error" => error})
  end

  defp release_services(state) do
    {services, actions} = Service.close(state.services)
    apply_actions(%{state | services: services}, actions)
  rescue
    _error -> state
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
          state = %{state | provider_session_id: session_id}
          apply_actions(state, session_opened(state, result))
        else
          reply_error(state, from, {:invalid_session_response, result})
        end

      {:error, reason} ->
        reply_error(state, from, reason)
    end
  end

  defp complete_rpc(state, {:ask, verb, from}, message) do
    case rpc_result(message) do
      {:ok, result} -> GenServer.reply(from, {:ok, state.dialect.answer(verb, result, state)})
      {:error, reason} -> GenServer.reply(from, {:error, reason})
    end

    state
  end

  defp complete_rpc(state, pending, message) do
    apply_actions(state, state.dialect.handle_rpc(pending, message, state))
  end

  # The open result is otherwise consumed for its session id alone. `Dialect.verify!/1`
  # pins an exact callback list, so this stays an optional export: a dialect that has
  # something to say about its own open result (ACP session modes) defines
  # `session_opened/2`; one that does not is silent, and the contract is unchanged.
  defp session_opened(state, result) do
    dialect = state.dialect

    if Code.ensure_loaded?(dialect) and function_exported?(dialect, :session_opened, 2),
      do: dialect.session_opened(result, state),
      else: []
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

  # A request id the services parked earlier — a `terminal/wait_for_exit` whose child has
  # now exited, or one whose terminal was released out from under it. Answering is the
  # transport's job because only it holds the socket.
  defp apply_action({:pending, id, reply}, state) do
    _ = write_service_reply(state, id, reply)
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
      {_id, {:ask, _verb, from}} -> GenServer.reply(from, {:error, reason})
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

  # Exactly the four fields `Jido.Harness.SessionRequestValidator` normalizes a
  # configuration to. Merged by name rather than with `struct!/2` so a key that somehow
  # reached here without passing the validator cannot raise inside a live session.
  @configurable_fields [:model, :reasoning_effort, :approval_mode, :sandbox_mode]

  defp configured_request(request, changes) do
    Enum.reduce(@configurable_fields, request, fn field, request ->
      case Map.fetch(changes, field) do
        {:ok, value} -> Map.put(request, field, value)
        :error -> request
      end
    end)
  end

  defp configured_env(config) do
    config[:env] || config["env"] || %{}
  end
end
