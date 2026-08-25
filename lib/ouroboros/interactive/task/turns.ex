defmodule Ouroboros.Interactive.Task.Turns do
  @moduledoc false

  alias Jido.Harness.{Session, TurnRequest}
  alias Ouroboros.Interactive.State
  alias Ouroboros.Interactive.Task
  alias Ouroboros.Provider
  alias Ouroboros.Runtime.Exposure
  alias Ouroboros.Workspace.Path, as: WorkspacePath

  def dispatch_turn(runtime, mode, id, input, opts)
      when mode in [:message, :follow_up] and is_binary(id) and is_list(opts) do
    with :ok <- validate_turn_id(id),
         true <- Keyword.keyword?(opts) || {:error, :invalid_turn_options},
         {:ok, request} <- build_turn_request(runtime.session.provider, input, opts),
         {:ok, request} <- authorize_turn_attachments(request, runtime.session.workspace),
         :ok <- ensure_serializable(request),
         :ok <- ensure_secret_free_options(request),
         :ok <- ensure_exposable_turn(runtime.session, request),
         turn = State.new_turn(id, mode, request) do
      case Map.fetch(runtime.session.turns, id) do
        {:ok, existing} ->
          cond do
            existing.fingerprint != turn.fingerprint ->
              {:error, {:turn_id_conflict, id}, runtime}

            # These are not acknowledgements. `:dispatching` is the last durable state
            # both before a recovered send and after Harness accepted a turn whose
            # correlation checkpoint failed; `:ambiguous` means the Harness call exited
            # without a trustworthy answer. Replaying either as `{:ok, existing}` makes
            # a stable-id client clear its input even though nothing proved the turn was
            # accepted. Keep the outcome unknown and let polling/transcript evidence
            # reconcile it without ever dispatching a duplicate here.
            existing.status in [:dispatching, :ambiguous] ->
              {:error, {:turn_dispatch_ambiguous, id}, runtime}

            true ->
              {:ok, existing, runtime}
          end

        :error ->
          case unresolved_dispatches(runtime.session) do
            [] -> persist_and_dispatch_turn(runtime, turn, request)
            ids -> {:error, {:turn_dispatch_unresolved, ids}, runtime}
          end
      end
    else
      false -> {:error, :invalid_turn_options, runtime}
      {:error, reason} -> {:error, reason, runtime}
    end
  end

  def dispatch_turn(runtime, _mode, _id, _input, _opts),
    do: {:error, :invalid_turn_request, runtime}

  defp persist_and_dispatch_turn(runtime, turn, request) do
    session =
      %{runtime.session | turns: Map.put(runtime.session.turns, turn.id, turn)} |> State.touch()

    case Task.persist(runtime, session, []) do
      {:ok, runtime} ->
        dispatch_persisted_turn(runtime, turn, request)

      {:error, runtime} ->
        {:error, {:turn_intent_checkpoint_failed, :storage_error}, runtime}
    end
  end

  def dispatch_persisted_turn(runtime, turn, request) do
    with {:ok, harness_request} <- expose_turn_request(runtime.session, request) do
      call =
        case turn.mode do
          :message -> fn id -> Session.send_message(id, harness_request) end
          :follow_up -> fn id -> Session.follow_up(id, harness_request) end
        end

      case Task.with_harness_session(runtime, call) do
        {:ok, harness_turn_id} ->
          updated =
            turn
            |> Map.put(:harness_turn_id, harness_turn_id)
            |> Map.put(:status, if(turn.mode == :follow_up, do: :queued, else: :running))
            |> State.touch_turn()

          session =
            %{runtime.session | turns: Map.put(runtime.session.turns, turn.id, updated)}
            |> State.touch()

          case Task.persist(runtime, session, []) do
            {:ok, runtime} ->
              {:ok, updated, Task.schedule_poll(runtime, 0)}

            {:error, runtime} ->
              {:error, {:turn_dispatch_checkpoint_failed, :dispatch_may_have_started, turn.id},
               Task.schedule_poll(runtime, 0)}
          end

        {:error, reason}
        when is_tuple(reason) and elem(reason, 0) in [:harness_call_exception, :harness_call_exit] ->
          ambiguous =
            turn
            |> Map.put(:status, :ambiguous)
            |> Map.put(:error, Task.durable(reason))
            |> State.touch_turn()

          session =
            %{runtime.session | turns: Map.put(runtime.session.turns, turn.id, ambiguous)}
            |> State.touch()

          case Task.persist(runtime, session, []) do
            {:ok, runtime} ->
              {:error, {:turn_dispatch_ambiguous, turn.id},
               Task.reply_turn_waiters(runtime, turn.id)}

            {:error, runtime} ->
              {:error, {:turn_dispatch_ambiguous, turn.id, :checkpoint_failed}, runtime}
          end

        {:error, reason} ->
          failed =
            turn
            |> Map.put(:status, :failed)
            |> Map.put(:error, Task.durable(reason))
            |> State.touch_turn()

          session =
            %{runtime.session | turns: Map.put(runtime.session.turns, turn.id, failed)}
            |> State.touch()

          case Task.persist(runtime, session, []) do
            {:ok, runtime} ->
              {:error, {:turn_dispatch_failed, reason}, Task.reply_turn_waiters(runtime, turn.id)}

            {:error, runtime} ->
              # Harness refused this call synchronously, but the failed checkpoint leaves
              # the durable turn at `:dispatching`. Recovery still owns that intent and
              # may send it once the Harness session becomes idle, so the caller cannot
              # safely mint a replacement id. Preserve both the reconciliation id and the
              # original refusal as a diagnostic while classifying the outcome unknown.
              {:error,
               {:turn_dispatch_checkpoint_failed, :dispatch_may_have_started, turn.id,
                {:harness_refused, reason}}, Task.schedule_poll(runtime, 0)}
          end
      end
    else
      {:error, reason} ->
        failed =
          turn
          |> Map.put(:status, :failed)
          |> Map.put(:error, Task.durable(reason))
          |> State.touch_turn()

        session =
          %{runtime.session | turns: Map.put(runtime.session.turns, turn.id, failed)}
          |> State.touch()

        case Task.persist(runtime, session, []) do
          {:ok, runtime} ->
            {:error, {:turn_dispatch_failed, reason}, Task.reply_turn_waiters(runtime, turn.id)}

          {:error, runtime} ->
            # Exposure failed before Harness was called, but the only durable record is
            # still `:dispatching`. Recovery owns that intent and can send it after the
            # capture is repaired, so a fresh caller id could duplicate the recovered turn.
            {:error,
             {:turn_dispatch_checkpoint_failed, :dispatch_may_have_started, turn.id,
              {:request_exposure_failed, reason}}, Task.schedule_poll(runtime, 0)}
        end
    end
  end

  defp expose_turn_request(session, request) do
    if Map.get(session.options, :runtime_exposure, true) do
      Exposure.wrap_turn_request_capture(request, Map.get(session, :runtime_snapshot))
    else
      {:ok, request}
    end
  end

  defp ensure_exposable_turn(session, %{prompt: prompt}) when is_binary(prompt) do
    if Map.get(session.options, :runtime_exposure, true) and
         Ouroboros.AgentProfile.reserved_delimiter?(prompt) do
      {:error, {:reserved_prompt_delimiter, :prompt}}
    else
      :ok
    end
  end

  defp ensure_exposable_turn(_session, _request), do: :ok

  defp build_turn_request(provider, input, opts) do
    allowed = [:attachments, :reasoning_effort, :output_schema, :metadata, :provider_options]

    case Enum.find(Keyword.keys(opts), &(&1 not in allowed)) do
      nil ->
        attrs =
          case input do
            prompt when is_binary(prompt) ->
              Map.put(Map.new(opts), :prompt, prompt)

            map when is_map(map) ->
              Map.merge(map, Map.new(opts))

            list when is_list(list) ->
              if Keyword.keyword?(list), do: Map.merge(Map.new(list), Map.new(opts)), else: list

            other ->
              other
          end

        with {:ok, request} <- TurnRequest.new(attrs) do
          {:ok, Provider.apply_runtime_provider_policy(request, provider)}
        end

      key ->
        {:error, {:unknown_turn_option, key}}
    end
  end

  def authorize_turn_attachments(%TurnRequest{attachments: []} = request, _workspace),
    do: {:ok, request}

  def authorize_turn_attachments(%TurnRequest{} = request, workspace) do
    with {:ok, root} <- WorkspacePath.canonicalize(workspace),
         {:ok, attachments} <- canonical_attachments(request.attachments, root) do
      {:ok, %{request | attachments: attachments}}
    else
      {:error, {:attachment_outside_workspace, _path} = reason} -> {:error, reason}
      {:error, {:invalid_attachment, _path, _reason} = reason} -> {:error, reason}
      {:error, reason} -> {:error, {:invalid_attachment_workspace, reason}}
    end
  end

  defp canonical_attachments(attachments, root) do
    Enum.reduce_while(attachments, {:ok, []}, fn path, {:ok, authorized} ->
      candidate =
        if Path.type(path) == :absolute,
          do: path,
          else: Path.join(root, path)

      lexical = Path.expand(candidate)

      cond do
        not WorkspacePath.within?(lexical, root) ->
          {:halt, {:error, {:attachment_outside_workspace, path}}}

        true ->
          case WorkspacePath.canonicalize_file(candidate) do
            {:ok, canonical} ->
              if WorkspacePath.within?(canonical, root) do
                {:cont, {:ok, [canonical | authorized]}}
              else
                {:halt, {:error, {:attachment_outside_workspace, path}}}
              end

            {:error, reason} ->
              {:halt, {:error, {:invalid_attachment, path, reason}}}
          end
      end
    end)
    |> case do
      {:ok, authorized} -> {:ok, Enum.reverse(authorized)}
      {:error, reason} -> {:error, reason}
    end
  end

  def finish_turn(runtime, turn_id, result) do
    case Map.fetch(runtime.session.turns, turn_id) do
      :error ->
        runtime

      {:ok, turn} ->
        status =
          if result.status in [:completed, :failed, :interrupted],
            do: result.status,
            else: :ambiguous

        updated =
          turn
          |> Map.put(:status, status)
          |> Map.put(:result, turn_result_summary(result))
          |> Map.put(:error, Task.durable(result.error))
          |> State.touch_turn()

        session =
          runtime.session
          |> put_in([Access.key(:turns), turn_id], updated)
          |> Task.maybe_provider_session(result.provider_session_id)
          |> State.touch()

        case Task.persist(runtime, session, []) do
          {:ok, runtime} -> Task.reply_turn_waiters(runtime, turn_id)
          {:error, runtime} -> runtime
        end
    end
  end

  # An ambiguity already recorded is not relabelled by a later, less specific one: the
  # first observation is the one this coordinator actually made. A turn finalised
  # outcome-unknown at a resume would otherwise be rewritten on the next poll by the new
  # Harness session's entirely correct "I have never heard of that turn" — a sentence
  # about a session that did not run it. It also stops a permanently unresolvable turn
  # from rewriting the whole session aggregate to disk every 25 ms to record the same
  # reason it already holds.
  def mark_turn_ambiguous(runtime, turn_id, reason) do
    case Map.fetch(runtime.session.turns, turn_id) do
      {:ok, %{status: :ambiguous}} ->
        runtime

      {:ok, turn} ->
        turn =
          turn
          |> Map.put(:status, :ambiguous)
          |> Map.put(:error, Task.durable(reason))
          |> State.touch_turn()

        session =
          %{runtime.session | turns: Map.put(runtime.session.turns, turn_id, turn)}
          |> State.touch()

        case Task.persist(runtime, session, []) do
          {:ok, runtime} -> Task.reply_turn_waiters(runtime, turn_id)
          {:error, runtime} -> runtime
        end

      :error ->
        runtime
    end
  end

  def unresolved_dispatches(session) do
    session.turns
    |> Enum.filter(fn {_id, turn} ->
      turn.status == :dispatching and is_nil(turn.harness_turn_id)
    end)
    |> Enum.map(&elem(&1, 0))
    |> Enum.sort()
  end

  defp turn_result_summary(result) do
    %{
      session_id: result.session_id,
      turn_id: result.turn_id,
      provider: result.provider,
      provider_session_id: result.provider_session_id,
      status: result.status,
      text: Task.durable(result.text),
      text_truncated?: result.text_truncated?,
      usage: Task.durable(result.usage),
      metadata: Task.durable(result.metadata)
    }
  end

  defp validate_turn_id(id) do
    if String.trim(id) == "", do: {:error, :invalid_turn_id}, else: :ok
  end

  defp ensure_serializable(value) do
    if serializable?(value), do: :ok, else: {:error, :non_serializable_turn_request}
  end

  defp ensure_secret_free_options(%TurnRequest{} = request) do
    private_options =
      request
      |> Map.from_struct()
      |> Map.take([:attachments, :output_schema, :metadata, :provider_options])

    if Jido.Harness.Redaction.redact(private_options) == private_options,
      do: :ok,
      else: {:error, :secret_bearing_turn_options}
  end

  defp serializable?(value)
       when is_pid(value) or is_port(value) or is_reference(value) or is_function(value),
       do: false

  defp serializable?(value) when is_struct(value),
    do: value |> Map.from_struct() |> serializable?()

  defp serializable?(value) when is_map(value),
    do: Enum.all?(value, fn {key, nested} -> serializable?(key) and serializable?(nested) end)

  defp serializable?(value) when is_list(value), do: Enum.all?(value, &serializable?/1)

  defp serializable?(value) when is_tuple(value),
    do: value |> Tuple.to_list() |> Enum.all?(&serializable?/1)

  defp serializable?(_value), do: true
end
