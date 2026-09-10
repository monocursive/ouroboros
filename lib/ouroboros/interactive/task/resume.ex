defmodule Ouroboros.Interactive.Task.Resume do
  @moduledoc false

  require Logger

  alias Ouroboros.Session
  alias Ouroboros.Interactive.{Event, State}
  alias Ouroboros.Interactive.Task

  @checkpoint_retry_ms 100

  def find_adoptable_session(ouroboros_id) do
    sessions = Task.safe_session_call(&Session.list/0)

    matches =
      if is_list(sessions) do
        Enum.filter(sessions, fn info ->
          metadata = info.metadata || %{}

          info.logical_id == ouroboros_id or
            (is_nil(info.logical_id) and
               (Map.get(metadata, :ouroboros_session_id) == ouroboros_id or
                  Map.get(metadata, "ouroboros_session_id") == ouroboros_id))
        end)
      else
        []
      end

    case {sessions, matches} do
      {{:error, reason}, _matches} ->
        {:error, reason}

      {_sessions, []} ->
        :not_found

      {_sessions, [info]} ->
        {:ok, info.session_id}

      {_sessions, infos} ->
        {:error, {:ambiguous_adoptable_sessions, Enum.map(infos, & &1.session_id)}}
    end
  end

  def adopt(%{session: %{runtime_id: previous}} = runtime, runtime_id)
      when is_binary(previous) and previous != runtime_id,
      do: adopt_resumed(runtime, runtime_id, previous)

  def adopt(runtime, runtime_id) do
    session =
      runtime.session
      |> Map.put(:runtime_id, runtime_id)
      |> State.touch()

    case Task.persist(runtime, session, []) do
      {:ok, runtime} ->
        Task.attach_runtime(runtime)

      {:error, runtime} ->
        Task.retry(runtime, :session_adoption_checkpoint_failed, :storage_error)
    end
  end

  # Settled means this coordinator has nothing left to decide about resuming: it already
  # attempted one, already explained why it could not, or was told to end the session.
  def settle_resume(runtime), do: %{runtime | resume_settled: true}

  # A runtime the registry no longer knows is not the same thing as a provider
  # session that is gone. `provider_session_id` is durable, and every transport that
  # declares it can be handed it again — `claude --resume`, Codex `thread/resume`, ACP
  # `session/load`. So the answer to "the registry does not know this runtime" is to open a
  # new one against the same provider session and keep going; `:lost` is what is left
  # when there is nothing to resume with, or when the provider refuses.
  #
  # Bounded to one decision per coordinator incarnation — one attempt, or one refusal
  # explained once. A provider that loses the session again ends the session honestly
  # instead of spinning up a start loop, and a genuinely transient outage still gets a
  # fresh decision the next time recovery restarts the coordinator.
  def resume_or_lose(%{session: %{close_intent: action}} = runtime, reason)
      when action in [:close, :kill] do
    case existing_replacement(runtime) do
      {:ok, id} -> adopt_resumed(runtime, id, runtime.session.runtime_id)
      :not_found -> finish_missing_shutdown(runtime, action, reason)
      {:error, error} -> Task.retry(runtime, :shutdown_discovery_failed, error)
    end
  end

  def resume_or_lose(%{resume_settled: true} = runtime, reason) do
    case existing_replacement(runtime) do
      {:ok, id} -> adopt_resumed(runtime, id, runtime.session.runtime_id)
      :not_found -> lose(runtime, reason)
      {:error, error} -> Task.retry(runtime, :resume_discovery_failed, error)
    end
  end

  def resume_or_lose(runtime, reason) do
    runtime = settle_resume(runtime)

    case State.resume_support(runtime.session) do
      :ok ->
        attempt_resume(runtime)

      {:error, unsupported} ->
        Logger.info(
          "interactive session #{runtime.session.id} cannot be resumed " <>
            "(#{inspect(unsupported)}); losing it"
        )

        lose(runtime, reason)
    end
  end

  defp existing_replacement(runtime) do
    case find_adoptable_session(runtime.session.id) do
      {:ok, id} when id != runtime.session.runtime_id -> {:ok, id}
      {:ok, _same} -> :not_found
      other -> other
    end
  end

  defp finish_missing_shutdown(runtime, action, reason) do
    session =
      runtime.session
      |> Task.finalize_unresolved_turns({:intentional_shutdown, action, reason})
      |> Map.put(:status, if(action == :kill, do: :cancelled, else: :closed))
      |> State.touch()

    case Task.persist(runtime, session, []) do
      {:ok, runtime} ->
        runtime
        |> Task.release_workspace()
        |> Task.reply_ready_waiters()
        |> Task.reply_all_terminal_turn_waiters()
        |> Task.schedule_retire()

      {:error, runtime} ->
        Task.retry(runtime, :shutdown_checkpoint_failed, :storage_error)
    end
  end

  defp attempt_resume(runtime) do
    session = runtime.session

    case State.unrequestable_reason(session) do
      nil ->
        case Task.safe_session_call(fn ->
               with {:ok, request} <-
                      Ouroboros.ReasoningEffort.session_request(State.request(session)),
                    do: Session.open(session.id, request)
             end) do
          {:ok, runtime_id} ->
            adopt_resumed(runtime, runtime_id, session.runtime_id)

          {:error, reason} ->
            lose(runtime, {:resume_failed, reason})
        end

      unrequestable ->
        lose(runtime, {:resume_failed, {:unrequestable_session_state, unrequestable}})
    end
  end

  # What the resume does and does not restore, recorded where a client can read it: the
  # journal and the turn ledger are Ouroboros's and survive intact; the conversation
  # itself is the provider's and comes back only as far as the provider carries it. The
  # turn that was in flight at the break is finalised outcome-unknown rather than
  # retried — the provider may well have completed it, and nothing here can tell.
  # The workspace lease is untouched: this coordinator has held it since admission and
  # goes on holding it, exactly as it does across a restart.
  defp adopt_resumed(runtime, runtime_id, previous_runtime_id) do
    session = runtime.session
    sequence = session.cursor + 1

    event =
      Event.from_runtime(
        session.id,
        sequence,
        :status,
        %{
          "kind" => "resumed",
          "provider_session_id" => session.provider_session_id,
          "previous_harness_session_id" => previous_runtime_id
        },
        harness_session_id: runtime_id,
        provider: session.provider,
        provider_session_id: session.provider_session_id
      )

    resumed =
      session
      |> Task.finalize_unresolved_turns({:session_resumed, :outcome_unknown})
      |> Map.put(:runtime_id, runtime_id)
      |> Map.put(:runtime_cursor, 0)
      |> Map.put(:runtime_generation, nil)
      |> Map.put(:sequence_offset, sequence)
      |> Map.put(:cursor, sequence)
      |> Map.put(:resumes, State.resumes(session) + 1)
      |> Map.put(:error, nil)
      |> Task.append_event(event)
      |> State.touch()

    case Task.persist(runtime, resumed, [event]) do
      {:ok, runtime} ->
        if runtime.session.close_intent in [:close, :kill],
          do:
            Task.safe_session_call(fn ->
              apply(Session, runtime.session.close_intent, [runtime_id])
            end)

        runtime
        |> Task.clear_retry()
        |> Task.reply_all_terminal_turn_waiters()
        |> Task.attach_runtime()

      # The replacement remains idle and discoverable by logical identity. Retry its
      # adoption before admitting any input, preserving this one resume attempt and
      # its sequence offset even if the coordinator also restarts before the retry.
      {:error, runtime} ->
        if runtime.runtime_monitor, do: Process.demonitor(runtime.runtime_monitor, [:flush])

        runtime
        |> Map.put(:attachment, nil)
        |> Map.put(:runtime_monitor, nil)
        |> Task.retry(:session_resume_checkpoint_failed, :storage_error)
    end
  end

  defp lose(runtime, reason) do
    session =
      runtime.session
      |> Task.finalize_unresolved_turns({:session_lost, reason})
      |> Map.put(:status, :lost)
      |> Map.put(:error, Task.durable(reason))
      |> State.touch()

    case Task.persist(runtime, session, []) do
      {:ok, runtime} ->
        runtime
        |> Task.release_workspace()
        |> Task.reply_ready_waiters()
        |> Task.reply_all_terminal_turn_waiters()
        |> Task.schedule_retire()

      {:error, runtime} ->
        Task.schedule_reconcile(runtime, @checkpoint_retry_ms)
    end
  end
end
