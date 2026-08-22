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

  ## Why this process is findable by name

  `info/1`, `compact/2` and `handoff/2` are not `SessionAdapter` callbacks — the harness
  has no notion of a context window or a curated handoff packet, so there is no worker
  method to pass them through, and the transport handle is private worker state. Rather
  than reach into that state, this process registers itself under its own
  `provider_session_id` in `Ouroboros.Provider.Native.Registry`, which the interactive
  coordinator already holds durably. Registration is best effort and never fails an
  open: a duplicate id (two coordinators resuming the same provider session at once) is
  a state this runtime does not create, and the honest answer for the loser is that
  these three verbs cannot reach a transport, not that the session refused to start.
  """

  use GenServer, restart: :temporary

  @behaviour Jido.Harness.SessionAdapter

  require Logger

  alias Jido.Harness.ApprovalResponse
  alias Jido.Harness.Event
  alias Jido.Harness.SessionAdapter
  alias Jido.Harness.TurnRequest
  alias Ouroboros.Provider.Native.Checkpoint
  alias Ouroboros.Provider.Native.Context
  alias Ouroboros.Provider.Native.Context.Archive
  alias Ouroboros.Provider.Native.Context.Compaction
  alias Ouroboros.Provider.Native.Context.Handoff
  alias Ouroboros.Provider.Native.Context.Window
  alias Ouroboros.Provider.Native.Loop
  alias Ouroboros.Provider.Native.Model
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Tools

  @startup_timeout 30_000
  @checkpoint_timeout 15_000

  @registry Ouroboros.Provider.Native.Registry

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

  @doc """
  Rewinds this session to the end of `to_turn` — D10's `/rewind`, and its honesty.

  `what` is `:files`, `:conversation`, or `:both`. `to_turn` is a turn id from a
  `provider_event` of kind `checkpoint`, or `0`/`:start` for "before anything this
  session did".

      {:ok, %{restored: [%{path: …, action: "restored" | "deleted"}],
              unrestorable: [%{path: … | nil, turn_id: …, reason: …}],
              turns: [turn ids], messages: n}}

  **`unrestorable` is the point of the return value.** Claude Code's rewind silently
  under-delivered (issue #18516) and §2.5 of the plan names that as a mistake with
  receipts, so this answers with both lists and a caller is expected to show the second
  one *before* the operator commits. Anything a `bash` command changed is in it, by turn,
  because a shell's effects are not checkpointed and never can be by a runtime that does
  not inspect the programs it runs.

  Both halves emit: one `file_change` carrying every restored path, and a `status`-kind
  `provider_event` naming the rewind. A rewind that left no trace in the transcript would
  be a change to the workspace that the transcript denies.

  Refused while a turn is running: rewinding underneath a loop that is mid-edit would
  race its own writes.
  """
  @spec rewind(pid(), String.t() | non_neg_integer() | :start, :files | :conversation | :both) ::
          {:ok, map()} | {:error, term()}
  def rewind(handle, to_turn, what \\ :both) when what in [:files, :conversation, :both],
    do: SessionAdapter.call(handle, {:rewind, to_turn, what}, 60_000)

  @doc """
  The turns this session can be rewound to, oldest first.

  The rewind menu, in the shape a client renders: turn id, when, how many files, which
  paths, and how many shell commands ran in it — the last being what tells an operator
  that a turn is only partly undoable before they choose it.
  """
  @spec rewind_points(pid()) :: {:ok, [map()]} | {:error, term()}
  def rewind_points(handle), do: SessionAdapter.call(handle, :rewind_points)

  @doc false
  def start_link({request, context}), do: GenServer.start_link(__MODULE__, {request, context})

  @doc """
  Finds the transport process serving one `provider_session_id`, or `nil`.

  The registry may not be running at all — the native provider is usable from a bare
  `Session.open/2` in a test with no Ouroboros application behind it — so an absent
  registry answers `nil` rather than raising.
  """
  @spec whereis(String.t()) :: pid() | nil
  def whereis(provider_session_id) when is_binary(provider_session_id) do
    case Registry.lookup(@registry, provider_session_id) do
      [{pid, _value}] -> pid
      [] -> nil
    end
  rescue
    ArgumentError -> nil
  catch
    :exit, _reason -> nil
  end

  def whereis(_provider_session_id), do: nil

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
      state = %{
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
        approvals: MapSet.new(),
        # ---- context engineering (D3/D9) ----
        prompt_context: nil,
        options: options,
        compact_at: Window.compact_at(options),
        keep_recent_tokens: Window.keep_recent_tokens(options),
        # The last request's size as the provider counted it, and the turn it was
        # counted on. Both are needed by the thrash guard, which asks "how many turns
        # ago", not "how long ago".
        context_used: 0,
        turns: 0,
        compactions: [],
        thrashing?: false,
        archives: [],
        handed_off_to: nil,
        plan: nil,
        # A lazily-loaded rule enters the conversation once per session, not once per
        # turn: the loop reports back what it injected so the next turn does not repeat it.
        rules_loaded: []
      }

      case build_context(state) do
        {:ok, state} ->
          register(provider_session_id)
          {:ok, state}

        {:error, reason} ->
          {:stop, reason}
      end
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  # Best effort, and deliberately not part of the process name: a registry that is not
  # running, or an id something else already holds, must not stop a session opening.
  defp register(provider_session_id) do
    _ = Registry.register(@registry, provider_session_id, nil)
    :ok
  rescue
    ArgumentError -> :ok
  catch
    :exit, _reason -> :ok
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

  # `configure` is one of the two things allowed to change the cached prefix, so it
  # rebuilds it here rather than letting the next turn discover a stale one. A change
  # that fails validation leaves both the session and its prefix untouched.
  def handle_call({:configure, changes}, _from, state) do
    with {:ok, state} <- apply_configuration(state, changes),
         {:ok, state} <- build_context(state) do
      {:reply, :ok, state}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call(:context_info, _from, state), do: {:reply, {:ok, context_info(state)}, state}

  def handle_call({:compact, _focus}, _from, %{loop: loop} = state) when not is_nil(loop),
    do: {:reply, {:error, :busy}, state}

  def handle_call({:compact, focus}, _from, state) do
    case run_compaction(state, focus, :manual) do
      {:ok, state, report} -> {:reply, {:ok, report}, state}
      {:error, reason, state} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:handoff, prompt, open_child?}, _from, state) do
    case start_handoff(state, prompt, open_child?) do
      {:ok, state, result} -> {:reply, {:ok, result}, state}
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
        session_grants: snapshot.session_grants,
        rules_loaded: Map.get(snapshot, :rules_loaded, state.rules_loaded)
    }

    _ = checkpoint(state)
    {:reply, :ok, state}
  end

  def handle_call({:checkpoint, _stale_turn_id, _snapshot}, _from, state),
    do: {:reply, :ok, state}

  def handle_call(:rewind_points, _from, state) do
    case Checkpoint.turns(state.session_dir) do
      {:ok, turns} -> {:reply, {:ok, Enum.map(turns, &Checkpoint.summary/1)}, state}
      {:error, _reason} = error -> {:reply, error, state}
    end
  end

  def handle_call({:rewind, _to_turn, _what}, _from, %{loop: loop} = state)
      when not is_nil(loop),
      do: {:reply, {:error, :busy}, state}

  def handle_call({:rewind, to_turn, what}, _from, state) do
    case rewind_files(state, to_turn, what) do
      {:ok, outcome} ->
        {state, truncated} = rewind_conversation(state, to_turn, what)
        outcome = Map.put(outcome, :messages, truncated)

        announce(state, to_turn, what, outcome)
        {:reply, {:ok, outcome}, state}

      {:error, _reason} = error ->
        {:reply, error, state}
    end
  end

  @impl GenServer
  def handle_info({:native_event, turn_id, event}, %{loop: %{turn_id: turn_id}} = state) do
    state = state |> track_approval(event) |> track_usage(event) |> track_plan(event)
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
    with {:ok, state} <- maybe_compact(state),
         {:ok, state} <- ensure_context(state) do
      owner = self()

      loop = %Loop{
        emit: fn event -> Kernel.send(owner, {:native_event, turn_id, event}) end,
        checkpoint: fn snapshot ->
          GenServer.call(owner, {:checkpoint, turn_id, snapshot}, @checkpoint_timeout)
        end,
        model_module: state.model_module,
        model_spec: state.model_spec,
        system: state.prompt_context.system,
        tool_specs: state.prompt_context.tools,
        context_window: state.prompt_context.context_window,
        rules: Context.rules(state.prompt_context),
        rules_loaded: state.rules_loaded,
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

      {:ok,
       %{
         state
         | loop: %{pid: task.pid, ref: task.ref, turn_id: turn_id},
           turns: state.turns + 1
       }}
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

  # ---------------------------------------------------------------- rewind

  defp rewind_files(_state, _to_turn, :conversation),
    do: {:ok, %{restored: [], unrestorable: [], turns: []}}

  defp rewind_files(state, to_turn, _files_or_both),
    do: Checkpoint.restore_files(state.session_dir, to_turn)

  defp rewind_conversation(state, _to_turn, :files), do: {state, length(state.messages)}

  defp rewind_conversation(state, to_turn, _conversation_or_both) do
    case Checkpoint.message_count_at(state.session_dir, to_turn) do
      {:ok, count} when count <= length(state.messages) ->
        state = %{state | messages: Enum.take(state.messages, count)}
        _ = checkpoint(state)
        {state, count}

      # A count this session cannot honour — a turn id it never recorded, or a
      # conversation already shorter than the mark — leaves the transcript alone. A
      # rewind that truncated to a number it could not justify would lose messages the
      # manifest never claimed to cover.
      _unusable ->
        {state, length(state.messages)}
    end
  end

  defp announce(state, to_turn, what, outcome) do
    if outcome.restored != [] do
      emit(state, %{
        type: :file_change,
        payload: %{
          "changes" =>
            Enum.map(outcome.restored, fn entry ->
              %{
                "path" => entry.path,
                "relative_path" => Path.relative_to(entry.path, state.scope.root),
                "kind" => if(entry.action == "deleted", do: "delete", else: "modify"),
                "diff" => "",
                "reason" => "rewind"
              }
            end),
          "status" => "completed"
        },
        turn_id: nil,
        request_id: nil
      })
    end

    emit(state, %{
      type: :provider_event,
      payload: %{
        "kind" => "status",
        "event" => "rewind",
        "to_turn" => to_string(to_turn),
        "what" => Atom.to_string(what),
        "restored" => length(outcome.restored),
        "unrestorable" => Enum.map(outcome.unrestorable, &describe_unrestorable/1),
        "messages" => outcome.messages
      },
      turn_id: nil,
      request_id: nil
    })
  end

  defp describe_unrestorable(%{path: nil, turn_id: turn_id, reason: reason}),
    do: %{"turn_id" => turn_id, "reason" => reason}

  defp describe_unrestorable(%{path: path} = entry),
    do: %{"path" => path, "reason" => Map.get(entry, :reason) || "could not be restored"}

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

  # ---------------------------------------------------------------- context (D3/D9)

  @doc """
  What this session's cached prefix and context meter currently say.

  Names, digests and numbers only — never the instruction text, never the conversation.
  The gateway surfaces this as part of `interactive.info`; the footer wants
  `prefix_fingerprint` and `context_window`/`context_used` from it.
  """
  @spec info(pid()) :: {:ok, map()} | {:error, term()}
  def info(handle), do: SessionAdapter.call(handle, :context_info)

  @doc """
  Compacts this session's conversation now, optionally focused.

  This is `/compact [focus]`. It returns the same report a client would have seen from
  the automatic path, so a caller can show "what was folded" without waiting for the
  threshold.
  """
  @spec compact(pid(), String.t() | nil) :: {:ok, map()} | {:error, term()}
  def compact(handle, focus \\ nil), do: SessionAdapter.call(handle, {:compact, focus})

  @doc """
  Starts a fresh native session in this workspace, seeded with a curated packet.

  Amp replaced compaction with Handoff because compaction produces "summary on top of
  summary" (R3 §5). This is that: rather than folding the conversation again, the
  operator gets a *new* session whose first message states the goal, the constraints, the
  progress, the decisions and the next steps, the files this session touched with their
  current hashes, the open plan items, and whatever the operator typed as `prompt`.

  Returns the new session's `provider_session_id`. The parent records `handed_off_to` and
  keeps running: a handoff is not a close, and deciding to end the parent is the
  operator's.

  ## `open_child`

  `true` (the default) opens the child transport here, inheriting this session's
  `context.owner` because a runtime-level handoff has nowhere else to send events.

  `false` writes the packet, names the child, and stops. That is the shape the
  interactive plane needs: there, the child is a *session* with its own coordinator and
  its own harness worker, and it opens its own transport from the checkpoint this call
  already wrote. Opening one here as well would put two processes on one
  `provider_session_id` and — because the worker adopts the `provider_session_id` of any
  adapter event it receives ([session/worker.ex:289](../../../../deps/jido_harness/lib/jido_harness/session/worker.ex))
  — the orphan's `native_ready` would rename the *parent's* provider session to the
  child's.
  """
  @spec handoff(pid(), String.t() | nil, keyword()) :: {:ok, map()} | {:error, term()}
  def handoff(handle, prompt \\ nil, opts \\ []),
    do: SessionAdapter.call(handle, {:handoff, prompt, Keyword.get(opts, :open_child, true)})

  # ---------------------------------------------------------------- prefix

  defp build_context(state) do
    case Context.build(context_options(state)) do
      {:ok, context} -> {:ok, %{state | prompt_context: context}}
      {:error, _reason} = error -> error
    end
  end

  defp context_options(state) do
    [
      system_prompt: state.request.system_prompt,
      cwd: state.scope.root,
      add_dirs: state.scope.roots -- [state.scope.root],
      sandbox_mode: state.scope.sandbox_mode,
      approval_mode: state.approval_mode,
      tools: Tools.specs(state.request.allowed_tools, state.request.disallowed_tools),
      model_module: state.model_module,
      model_spec: state.model_spec,
      reasoning_effort: state.reasoning_effort,
      compactions: length(state.compactions)
    ]
  end

  # The prefix is built once and reused. It is rebuilt only where the operator changed
  # the session — `configure` — or where compaction rewrote the conversation, which are
  # the two documented cache invalidators this runtime can cause. Rebuilding it per turn
  # would produce the same bytes today and would be a standing invitation to put
  # something turn-dependent in it tomorrow.
  defp ensure_context(%{prompt_context: nil} = state), do: build_context(state)
  defp ensure_context(state), do: {:ok, state}

  defp context_info(state) do
    context = state.prompt_context

    base =
      if context,
        do: Context.info(context),
        else: %{prefix_fingerprint: nil, context_window: nil}

    Map.merge(base, %{
      provider_session_id: state.provider_session_id,
      context_used: state.context_used,
      compact_at: state.compact_at,
      keep_recent_tokens: state.keep_recent_tokens,
      messages: length(state.messages),
      compaction_thrashing: state.thrashing?,
      compactions: Enum.reverse(state.compactions),
      archives: Enum.reverse(state.archives),
      handed_off_to: state.handed_off_to
    })
  end

  # ---------------------------------------------------------------- the meter

  # The size reported is whatever the provider counted for the last request. A session
  # that has not spent a turn yet reports zero used, which is true, rather than an
  # estimate of what the prefix will cost, which would be a guess presented as a
  # measurement.
  defp track_usage(state, %{type: :usage, payload: payload}) when is_map(payload) do
    case Window.used(payload) do
      used when used > 0 -> %{state | context_used: used}
      _none -> state
    end
  end

  defp track_usage(state, _event), do: state

  # ---------------------------------------------------------------- compaction

  # The thrash latch is deliberately permanent for the *automatic* path. "Stop rather
  # than loop" means stop: a session whose tail alone fills the window will keep meeting
  # the threshold on every turn, and re-arming would be the loop the guard exists to
  # prevent. The operator's own `/compact` is not latched — they were told what happened
  # and what to change, and overruling them would be a different mistake.
  defp maybe_compact(%{thrashing?: true} = state), do: {:ok, state}

  defp maybe_compact(state) do
    window = state.prompt_context && state.prompt_context.context_window

    if Window.over_threshold?(state.context_used, window, state.compact_at) do
      case run_compaction(state, nil, :automatic) do
        {:ok, state, _report} -> {:ok, state}
        # A refused compaction is not a refused turn. The operator has been told, in an
        # event with the reason in it, and the turn goes to the model as it stands —
        # which the provider may still reject for length, honestly, rather than this
        # runtime failing it pre-emptively on a threshold it just admitted it cannot act
        # on.
        {:error, _reason, state} -> {:ok, state}
      end
    else
      {:ok, state}
    end
  end

  # Two compactions inside three turns is not a context that needs folding, it is a
  # threshold or a tail that cannot fit. Say so once, as a `status` provider event, and
  # stop — Claude Code's thrashing detection with the reason made visible.
  defp run_compaction(state, focus, trigger) do
    if thrash_guard(state) do
      emit(state, %{
        type: :provider_event,
        payload: %{
          "kind" => "status",
          "status" => "compaction_thrashing",
          "message" =>
            "two compactions within three turns; stopping rather than looping. " <>
              "Raise `keep_recent_tokens`, lower `compact_at`, or hand off to a new " <>
              "session with the packet this one can build."
        },
        turn_id: nil,
        request_id: nil
      })

      {:error, :compaction_thrashing, %{state | thrashing?: true}}
    else
      do_compaction(state, focus, trigger)
    end
  end

  defp do_compaction(state, focus, trigger) do
    {:ok, outcome} =
      Compaction.compact(state.messages,
        keep_recent_tokens: state.keep_recent_tokens,
        focus: focus,
        summarize: summariser(state)
      )

    case archive(state, outcome.archived) do
      {:ok, entry} -> apply_compaction(state, outcome, entry, trigger)
      {:error, reason} -> refuse_compaction(state, reason)
    end
  end

  # "Compaction always leaves the archive" is an invariant, so it decides the outcome
  # rather than decorating it: messages that could not be written down are not dropped.
  # The session keeps its whole conversation, the operator is told why, and the provider
  # may still refuse the next request for length — which is a truthful failure rather
  # than a silent loss.
  defp refuse_compaction(state, reason) do
    Logger.warning("native compaction refused: archive unwritable (#{inspect(reason)})")

    emit(state, %{
      type: :provider_event,
      payload: %{
        "kind" => "status",
        "status" => "compaction_refused",
        "reason" => inspect(reason),
        "message" =>
          "the conversation was not compacted because its pre-compaction transcript " <>
            "could not be archived. Nothing was dropped."
      },
      turn_id: nil,
      request_id: nil
    })

    {:error, {:archive_unwritable, reason}, state}
  end

  defp apply_compaction(state, outcome, entry, trigger) do
    report = %{
      trigger: Atom.to_string(trigger),
      turn: state.turns,
      archived_messages: length(outcome.archived),
      archive_id: entry && entry.id,
      elided_tool_results: outcome.elided,
      summary_tokens: outcome.summary_tokens,
      before_tokens: outcome.before_tokens,
      after_tokens: outcome.after_tokens,
      summarised: outcome.summarised
    }

    state = %{
      state
      | messages: outcome.messages,
        compactions: [report | state.compactions],
        archives: if(entry, do: [entry | state.archives], else: state.archives),
        prompt_context: Context.compacted(state.prompt_context, context_options(state)),
        context_used: 0
    }

    # Checkpoint before broadcast, the same order every other durable write in this
    # process follows: a client told the conversation was folded must never be able to
    # restart onto a conversation that was not.
    _ = checkpoint(state)

    emit(state, %{
      type: :provider_event,
      payload: compaction_payload(report, outcome),
      turn_id: nil,
      request_id: nil
    })

    {:ok, state, report}
  end

  defp thrash_guard(%{compactions: [%{turn: turn} | _rest]} = state), do: state.turns - turn <= 3
  defp thrash_guard(_state), do: false

  defp compaction_payload(report, outcome) do
    %{
      "kind" => "compaction",
      "trigger" => report.trigger,
      "archived_messages" => report.archived_messages,
      "archive_id" => report.archive_id,
      "elided_tool_results" => report.elided_tool_results,
      "summary_tokens" => report.summary_tokens,
      "before_tokens" => report.before_tokens,
      "after_tokens" => report.after_tokens,
      "summary" => outcome.summary
    }
    |> Map.reject(fn {_key, value} -> is_nil(value) end)
  end

  # Nothing to archive is not a failed archive: eliding tool results alone dropped no
  # message, so there is no transcript to keep.
  defp archive(_state, []), do: {:ok, nil}

  defp archive(state, messages),
    do: Archive.write(state.session_dir, messages, event_limit: state.checkpoint_limit)

  # The summariser is one more call on the same model module the turn uses, with no
  # tools. It is deliberately not the loop: a summary that could call `bash` would be a
  # second agent nobody asked for.
  defp summariser(state) do
    fn %{messages: messages, instruction: instruction} ->
      request = %{
        model: state.model_spec,
        system: instruction,
        messages: messages ++ [%{role: :user, content: instruction}],
        tools: [],
        reasoning_effort: nil,
        max_tokens: nil
      }

      case Model.stream(state.model_module, request, []) do
        {:ok, stream} -> {:ok, collect_text(stream)}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defp collect_text(stream) do
    stream
    |> Enum.reduce([], fn
      {:text, delta}, acc when is_binary(delta) -> [acc, delta]
      _other, acc -> acc
    end)
    |> IO.iodata_to_binary()
  rescue
    _error -> ""
  catch
    :exit, _reason -> ""
  end

  # ---------------------------------------------------------------- handoff

  # The packet is made durable *before* the child is started. A handoff whose child
  # failed to start is then still a handoff the operator can open by id, rather than a
  # summary that existed only inside a call that returned an error.
  defp start_handoff(state, prompt, open_child?) do
    packet =
      Handoff.packet(
        summary: handoff_summary(state),
        files: Map.keys(state.reads),
        plan: state.plan,
        prompt: prompt,
        workspace: state.scope.root,
        parent: state.provider_session_id
      )

    child_id = Paths.new_session_id()
    seeded = [%{role: :user, content: packet}]

    with {:ok, checkpoint_path, _durable?} <- Checkpoint.locate(child_id),
         :ok <- Checkpoint.write(checkpoint_path, seeded, event_limit: state.checkpoint_limit),
         {:ok, pid} <- maybe_open_child(state, child_id, open_child?) do
      result = %{
        provider_session_id: child_id,
        pid: pid,
        packet_bytes: byte_size(packet),
        files: length(Map.keys(state.reads)),
        parent: state.provider_session_id
      }

      emit(state, %{
        type: :provider_event,
        payload: %{
          "kind" => "handoff",
          "provider_session_id" => child_id,
          "packet_bytes" => result.packet_bytes,
          "files" => result.files
        },
        turn_id: nil,
        request_id: nil
      })

      {:ok, %{state | handed_off_to: child_id}, result}
    end
  end

  # The child inherits this session's request — same workspace, same tools, same posture —
  # with its own id and no caller-supplied resume. It also inherits `context.owner`,
  # because a runtime-level handoff has nowhere else to send events; the gateway replaces
  # the owner when it wires the verb, and that is the one thing this function does not
  # decide.
  defp open_child(state, child_id) do
    request = %{state.request | provider_session_id: child_id}
    open(request, state.context)
  end

  # `{:ok, nil}` rather than a separate result shape: the caller that asked for no child
  # process is the one that is about to open it properly, and the packet on disk is the
  # thing a handoff actually is.
  defp maybe_open_child(state, child_id, true), do: open_child(state, child_id)
  defp maybe_open_child(_state, _child_id, false), do: {:ok, nil}

  # A handoff summarises the whole conversation, not the part past `keep_recent_tokens`:
  # the new session gets no verbatim tail, so a summary that stopped short of the last
  # twenty thousand tokens would hand over a packet missing the most recent work.
  defp handoff_summary(%{messages: []}), do: nil

  defp handoff_summary(state) do
    instruction = Compaction.summary_instruction(nil)

    case summariser(state).(%{messages: state.messages, focus: nil, instruction: instruction}) do
      {:ok, summary} when is_binary(summary) ->
        case String.trim(summary) do
          "" -> Compaction.structural_summary(state.messages, nil)
          text -> text
        end

      _failed ->
        Compaction.structural_summary(state.messages, nil)
    end
  end

  defp track_plan(state, %{type: :plan_updated, payload: payload}) when is_map(payload),
    do: %{state | plan: payload}

  defp track_plan(state, _event), do: state
end
