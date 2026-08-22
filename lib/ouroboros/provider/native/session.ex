defmodule Ouroboros.Provider.Native.Session do
  @moduledoc """
  The interactive transport for the native agent: one supervised GenServer per session.

  `Jido.Harness.SessionAdapter` asks for an opaque handle with `open/send/interrupt/close`
  and the three optional callbacks. This transport answers all of them, which is the
  whole point — the loop is in this VM, so `steer/3`, `respond_approval/3`, and
  `configure/2` are things this runtime can actually do rather than declare.

  ## Division of labour with the session worker

  The worker owns session and turn *bookkeeping*: it appends `session_started`,
  `session_ready`, `session_idle`, `input_accepted`, `turn_started`, `queue_changed`,
  `approval_resolved`, and it finishes a turn when it sees a terminal event or when its
  own `interrupt` call returns `:ok`. This process owns everything a provider produces:
  text, thinking, tool calls, tool results, file changes, plans, usage, approval
  requests, and the terminal turn event.

  Approvals therefore have two timers by design. The worker starts one from the
  session's `approval_timeout_ms` and denies through `respond_approval/3` when it fires;
  this process starts the same one in the loop so that a session driven directly — a
  test, or a future embedding — still denies on time. Whichever fires first wins and the
  other's `respond_approval` finds nothing pending, which is a no-op.

  ## Checkpoint before broadcast

  A turn's conversation is written to `Ouroboros.Provider.Native.Checkpoint` *before*
  the terminal turn event reaches the owner. The failure that ordering chooses is
  replaying one turn after a crash, over losing one — the same rule the interactive
  coordinator already follows for its own checkpoints.
  """

  use GenServer, restart: :temporary

  @behaviour Jido.Harness.SessionAdapter

  require Logger

  alias Jido.Harness.ApprovalResponse
  alias Jido.Harness.Event
  alias Jido.Harness.SessionAdapter
  alias Jido.Harness.TurnRequest
  alias Ouroboros.Provider.Native.Checkpoint
  alias Ouroboros.Provider.Native.Loop
  alias Ouroboros.Provider.Native.Model
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Prompt
  alias Ouroboros.Provider.Native.Tools

  @startup_timeout 30_000
  @checkpoint_timeout 15_000

  # ---------------------------------------------------------------- adapter

  @impl Jido.Harness.SessionAdapter
  def open(request, context) do
    case DynamicSupervisor.start_child(
           Jido.Harness.SessionTransportSupervisor,
           {__MODULE__, {request, context}}
         ) do
      {:ok, pid} ->
        case SessionAdapter.call(pid, :initialize, @startup_timeout) do
          {:ok, provider_session_id} ->
            SessionAdapter.emit(
              context.owner,
              Event.new!(
                type: :provider_event,
                provider: context.provider,
                provider_session_id: provider_session_id,
                payload: %{"kind" => "native_ready"}
              )
            )

            {:ok, pid}

          {:error, _reason} = error ->
            DynamicSupervisor.terminate_child(Jido.Harness.SessionTransportSupervisor, pid)
            error
        end

      {:error, _reason} = error ->
        error
    end
  catch
    :exit, reason -> {:error, reason}
  end

  @impl Jido.Harness.SessionAdapter
  def send(handle, %TurnRequest{} = request, turn_id),
    do: SessionAdapter.call(handle, {:send, request, turn_id})

  @impl Jido.Harness.SessionAdapter
  def steer(handle, %TurnRequest{} = request, request_id),
    do: SessionAdapter.call(handle, {:steer, request, request_id})

  @impl Jido.Harness.SessionAdapter
  def interrupt(handle, turn_id), do: SessionAdapter.call(handle, {:interrupt, turn_id})

  @impl Jido.Harness.SessionAdapter
  def respond_approval(handle, request_id, %ApprovalResponse{} = response),
    do: SessionAdapter.call(handle, {:respond_approval, request_id, response})

  @impl Jido.Harness.SessionAdapter
  def configure(handle, changes), do: SessionAdapter.call(handle, {:configure, changes})

  @impl Jido.Harness.SessionAdapter
  def close(handle), do: SessionAdapter.call(handle, :close)

  @doc false
  def start_link({request, context}), do: GenServer.start_link(__MODULE__, {request, context})

  # ---------------------------------------------------------------- lifecycle

  @impl GenServer
  def init({request, context}) do
    options = Map.new(request.provider_options || %{})

    with {:ok, provider_session_id} <- session_id(request.provider_session_id),
         {:ok, scope} <-
           Paths.scope(request.cwd, request.add_dirs, Loop.sandbox_mode(request.sandbox_mode)),
         {:ok, model_spec} <- Loop.resolve_model(request.model),
         {:ok, session_dir, durable?} <- Paths.session_dir(provider_session_id),
         {:ok, checkpoint_path, _durable?} <- Checkpoint.locate(provider_session_id),
         {:ok, messages} <- restore(checkpoint_path, request.provider_session_id) do
      {:ok,
       %{
         request: request,
         context: context,
         provider_session_id: provider_session_id,
         scope: scope,
         session_dir: session_dir,
         checkpoint_path: checkpoint_path,
         checkpoint_durable?: durable?,
         checkpoint_limit: Checkpoint.limit(options),
         model_module: Model.module(),
         model_spec: model_spec,
         reasoning_effort: request.reasoning_effort,
         approval_mode: Loop.approval_mode(request.approval_mode),
         max_iterations: Loop.max_iterations(options, nil),
         tool_timeout_ms: Loop.tool_timeout(options),
         messages: messages,
         reads: %{},
         session_grants: MapSet.new(),
         loop: nil,
         approvals: MapSet.new()
       }}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl GenServer
  def handle_call(:initialize, _from, state),
    do: {:reply, {:ok, state.provider_session_id}, state}

  def handle_call({:send, _request, _turn_id}, _from, %{loop: loop} = state)
      when not is_nil(loop),
      do: {:reply, {:error, :busy}, state}

  def handle_call({:send, request, turn_id}, _from, state) do
    case start_turn(state, request, turn_id) do
      {:ok, state} -> {:reply, :ok, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:steer, _request, _request_id}, _from, %{loop: nil} = state),
    do: {:reply, {:error, :no_active_turn}, state}

  def handle_call({:steer, request, _request_id}, _from, state) do
    Kernel.send(state.loop.pid, {:native_steer, TurnRequest.text(request)})
    {:reply, :ok, state}
  end

  def handle_call({:interrupt, _turn_id}, _from, %{loop: nil} = state),
    do: {:reply, {:error, :not_active}, state}

  def handle_call({:interrupt, requested}, _from, state) do
    if requested in [:active, state.loop.turn_id] do
      Kernel.send(state.loop.pid, :native_interrupt)
      {:reply, :ok, state}
    else
      {:reply, {:error, :not_active}, state}
    end
  end

  def handle_call({:respond_approval, request_id, response}, _from, state) do
    if MapSet.member?(state.approvals, request_id) and state.loop do
      Kernel.send(state.loop.pid, {:native_approval, request_id, response})
      {:reply, :ok, %{state | approvals: MapSet.delete(state.approvals, request_id)}}
    else
      {:reply, {:error, :unknown_request}, state}
    end
  end

  def handle_call({:configure, changes}, _from, state) do
    case apply_configuration(state, changes) do
      {:ok, state} -> {:reply, :ok, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call(:close, _from, state) do
    state = stop_loop(state)
    _ = checkpoint(state)

    emit(state, %{
      type: :session_closed,
      payload: %{"reason" => "closed"},
      turn_id: nil,
      request_id: nil
    })

    {:stop, :normal, :ok, state}
  end

  # The loop calls this synchronously, immediately before it emits the terminal turn
  # event. Returning `:ok` from here is the guarantee that the conversation on disk is
  # at least as new as the event about to reach the owner.
  def handle_call({:checkpoint, turn_id, snapshot}, _from, %{loop: %{turn_id: turn_id}} = state) do
    state = %{
      state
      | messages: snapshot.messages,
        reads: snapshot.reads,
        session_grants: snapshot.session_grants
    }

    _ = checkpoint(state)
    {:reply, :ok, state}
  end

  def handle_call({:checkpoint, _stale_turn_id, _snapshot}, _from, state),
    do: {:reply, :ok, state}

  @impl GenServer
  def handle_info({:native_event, turn_id, event}, %{loop: %{turn_id: turn_id}} = state) do
    state = track_approval(state, event)
    emit(state, event)

    if event.type in [:turn_completed, :turn_failed, :turn_interrupted] do
      {:noreply, release(state)}
    else
      {:noreply, state}
    end
  end

  def handle_info({:native_event, _stale_turn_id, _event}, state), do: {:noreply, state}

  def handle_info({ref, :ok}, %{loop: %{ref: ref}} = state) do
    Process.demonitor(ref, [:flush])
    {:noreply, release(state)}
  end

  def handle_info({:DOWN, ref, :process, _pid, reason}, %{loop: %{ref: ref}} = state) do
    if reason != :normal do
      emit(state, %{
        type: :turn_failed,
        payload: %{"error" => "native loop crashed: #{inspect(reason)}", "reason" => "crash"},
        turn_id: state.loop.turn_id,
        request_id: nil
      })
    end

    {:noreply, release(state)}
  end

  def handle_info(_message, state), do: {:noreply, state}

  # A turn that ended leaves no loop and no pending approvals. Both are per-turn state:
  # a request_id from a finished turn must not be answerable afterwards.
  defp release(state), do: %{state | loop: nil, approvals: MapSet.new()}

  @impl GenServer
  def terminate(_reason, state) do
    _ = stop_loop(state)
    :ok
  rescue
    _error -> :ok
  end

  # ---------------------------------------------------------------- turns

  defp start_turn(state, request, turn_id) do
    with {:ok, system} <- system_prompt(state) do
      owner = self()

      loop = %Loop{
        emit: fn event -> Kernel.send(owner, {:native_event, turn_id, event}) end,
        checkpoint: fn snapshot ->
          GenServer.call(owner, {:checkpoint, turn_id, snapshot}, @checkpoint_timeout)
        end,
        model_module: state.model_module,
        model_spec: state.model_spec,
        system: system,
        scope: state.scope,
        session_dir: state.session_dir,
        session_id: state.context.session_id,
        provider_session_id: state.provider_session_id,
        turn_id: turn_id,
        reasoning_effort: request.reasoning_effort || state.reasoning_effort,
        approval_mode: state.approval_mode,
        allowed_tools: state.request.allowed_tools,
        disallowed_tools: state.request.disallowed_tools,
        messages: state.messages,
        reads: state.reads,
        session_grants: state.session_grants,
        max_iterations: state.max_iterations,
        tool_timeout_ms: state.tool_timeout_ms,
        approval_timeout_ms: state.request.approval_timeout_ms
      }

      prompt = TurnRequest.text(request)

      task =
        Task.Supervisor.async_nolink(Jido.Harness.SessionTaskSupervisor, fn ->
          {:ok, _finished} = Loop.run_turn(loop, prompt)
          :ok
        end)

      {:ok, %{state | loop: %{pid: task.pid, ref: task.ref, turn_id: turn_id}}}
    end
  end

  defp stop_loop(%{loop: nil} = state), do: state

  defp stop_loop(%{loop: loop} = state) do
    Process.demonitor(loop.ref, [:flush])
    _ = Task.Supervisor.terminate_child(Jido.Harness.SessionTaskSupervisor, loop.pid)
    %{state | loop: nil, approvals: MapSet.new()}
  end

  defp track_approval(state, %{type: :approval_requested, request_id: request_id})
       when is_binary(request_id),
       do: %{state | approvals: MapSet.put(state.approvals, request_id)}

  defp track_approval(state, _event), do: state

  defp emit(state, event) do
    SessionAdapter.emit(
      state.context.owner,
      Loop.to_event(event, state.context.provider, state.provider_session_id)
    )
  end

  # ---------------------------------------------------------------- config

  defp apply_configuration(state, changes) do
    Enum.reduce_while(changes, {:ok, state}, fn {key, value}, {:ok, state} ->
      case configure_one(state, normalize_key(key), value) do
        {:ok, state} -> {:cont, {:ok, state}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp configure_one(state, :model, value) when is_binary(value) and value != "",
    do: {:ok, %{state | model_spec: value}}

  defp configure_one(state, :reasoning_effort, value) when value in [:low, :medium, :high, nil],
    do: {:ok, %{state | reasoning_effort: value}}

  defp configure_one(state, :approval_mode, value)
       when value in [:default, :prompt, :auto_edit, :auto_approve],
       do: {:ok, %{state | approval_mode: Loop.approval_mode(value)}}

  # Sandbox mode changes the tools' own refusals, so it takes effect on the next tool
  # call, not the next turn — which is what `dynamic_configuration: :native` promises.
  defp configure_one(state, :sandbox_mode, value)
       when value in [:default, :read_only, :workspace_write] do
    {:ok, %{state | scope: %{state.scope | sandbox_mode: Loop.sandbox_mode(value)}}}
  end

  defp configure_one(_state, key, value),
    do: {:error, {:unsupported_configuration, key, value}}

  defp normalize_key(key) when is_atom(key), do: key

  defp normalize_key(key) when is_binary(key) do
    case key do
      "model" -> :model
      "reasoning_effort" -> :reasoning_effort
      "approval_mode" -> :approval_mode
      "sandbox_mode" -> :sandbox_mode
      other -> other
    end
  end

  # ---------------------------------------------------------------- resume

  # A caller-supplied id is validated as untrusted input before it becomes a directory
  # name; a session that names none gets a fresh node-embedded one.
  defp session_id(nil), do: {:ok, Paths.new_session_id()}

  defp session_id(id) do
    case Paths.validate_session_id(id) do
      :ok -> {:ok, id}
      {:error, _reason} = error -> error
    end
  end

  # Only a session that asked to resume reads a checkpoint. A fresh id has no history by
  # definition, and a corrupt file must fail the open rather than silently start an
  # empty session under an id whose transcript the operator believes still exists.
  defp restore(_path, nil), do: {:ok, []}

  defp restore(path, _requested) do
    case Checkpoint.read(path) do
      {:ok, messages} -> {:ok, messages}
      {:error, :no_checkpoint} -> {:ok, []}
      {:error, reason} -> {:error, {:checkpoint_unusable, reason}}
    end
  end

  defp checkpoint(state) do
    case Checkpoint.write(state.checkpoint_path, state.messages,
           event_limit: state.checkpoint_limit
         ) do
      :ok ->
        :ok

      {:error, reason} ->
        Logger.warning("native session checkpoint failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp system_prompt(state) do
    Prompt.build(
      system_prompt: state.request.system_prompt,
      cwd: state.scope.root,
      add_dirs: state.scope.roots -- [state.scope.root],
      sandbox_mode: state.scope.sandbox_mode,
      approval_mode: state.approval_mode,
      tools: Tools.specs(state.request.allowed_tools, state.request.disallowed_tools)
    )
  end
end
