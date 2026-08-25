defmodule Ouroboros.Gateway.Methods.Safe do
  @moduledoc false

  # `try/rescue/catch :exit` around every upstream call. Several planes *exit*
  # rather than return an error when they are down; a `:noproc` becomes `-32004`,
  # a `:timeout` becomes `-32005`, and anything else becomes `-32006` carrying the
  # Wire-encoded reason. None of them become a dead connection.

  alias Ouroboros.Gateway.Wire

  defp code(name), do: Ouroboros.Gateway.Methods.code(name)

  def safe(fun) do
    fun.()
  rescue
    error -> upstream_error(error)
  catch
    :exit, reason -> exit_result(reason)
    kind, reason -> upstream_error({kind, reason})
  end

  def reply({:ok, value}), do: {:ok, value}

  def reply(:not_found), do: not_found("no such record on this node")
  def reply({:error, :not_found}), do: not_found("no such record on this node")

  def reply({:error, {:agent_not_found, id}}),
    do: not_found("no agent #{inspect(id)} is visible from this node")

  def reply({:error, {:team_not_found, id}}),
    do: not_found("no team #{inspect(id)} is visible from this node")

  def reply({:error, {:session_not_terminal, status}}) do
    {:error, code(:upstream_error),
     "the session is still #{status}; close or kill it before removing the durable record",
     %{"reason" => "session_not_terminal", "status" => to_string(status)}}
  end

  def reply({:error, {:task_not_terminal, status}}) do
    {:error, code(:upstream_error),
     "the coding task is still #{status}; cancel it before removing the durable record",
     %{"reason" => "task_not_terminal", "status" => to_string(status)}}
  end

  def reply({:error, :control_disabled_or_unavailable}),
    do: unavailable("the control plane is disabled or not running on this node")

  def reply({:error, {:permissions_unavailable, _detail}}),
    do: unavailable("the permission engine is not running on this node")

  def reply({:error, :node_scope_is_operator_configuration}) do
    {:error, code(:upstream_error),
     "node-scope permission rules come from config :ouroboros, :permissions and are not written over the wire",
     %{"reason" => "node_scope_is_operator_configuration"}}
  end

  def reply({:error, {:unknown_permission_rule, id}}),
    do: not_found("no permission rule #{id} on this node")

  def reply({:error, {:signing_service_unavailable, _detail} = reason}),
    do: {:error, code(:unavailable), "the signing service did not answer", Wire.to_json(reason)}

  # A rejected title is the caller's mistake, not the runtime's, and the reason names
  # which rule it broke so a client can say so next to the field rather than in a toast.
  def reply({:error, {:invalid_title, %{reason: :too_long, limit: limit}}}) do
    invalid_params("params.title must be at most #{limit} characters after trimming")
  end

  def reply({:error, {:invalid_title, %{reason: :control_characters}}}) do
    invalid_params(
      "params.title must not contain control characters; it is drawn into one line of a list"
    )
  end

  def reply({:error, {:invalid_title, %{reason: reason}}})
      when reason in [:blank, :not_a_string] do
    invalid_params("params.title must be a nonempty string")
  end

  # A pruned cursor is the one upstream detail a client acts on rather than displays: it
  # restarts from the floor and marks the transcript as truncated below it. So the floor
  # travels as data under a named reason instead of inside a sentence.
  def reply({:error, {:cursor_pruned, floor}}) do
    {:error, code(:upstream_error),
     "the session no longer retains events at or below that cursor; replay from #{floor}",
     %{"reason" => "cursor_pruned", "floor" => floor}}
  end

  # Several planes bound themselves and answer `:timeout` rather than exiting. The request
  # may still have been accepted durably — `Ouroboros.Team` says so explicitly — so the
  # answer is the same "the gateway stopped waiting, the runtime did not" that a ceiling
  # breach gets, and it carries the same admission of not knowing.
  def reply({:error, :timeout}) do
    {:error, code(:upstream_timeout), "the runtime did not answer in time",
     %{"outcome" => "unknown"}}
  end

  def reply({:error, {:unavailable, message}}) when is_binary(message), do: unavailable(message)

  def reply({:error, {:owner_unavailable, owner}}) when is_atom(owner) do
    {:error, code(:unavailable), "session owner #{owner} is offline; Ouroboros is reconnecting",
     %{"reason" => "owner_unavailable", "node" => owner, "outcome" => "unknown"}}
  end

  def reply({:error, {:owner_unavailable, owner, detail}}) when is_atom(owner) do
    {:error, code(:unavailable),
     "session owner #{owner} did not answer; Ouroboros is reconnecting",
     %{
       "reason" => "owner_unavailable",
       "node" => owner,
       "detail" => Wire.to_json(detail),
       "outcome" => "unknown"
     }}
  end

  def reply({:error, reason}), do: turn_error_reply(reason)
  def reply(value), do: {:ok, value}

  # Answered in `interactive.start`'s shape, because a fork *is* a start and a client that
  # already knows how to open a created-but-not-ready session should not need a second
  # branch to open this one.
  def fork_reply({:ok, %{id: id, node: owner, ready: ready?, error: error}}) do
    {:ok,
     %{
       "id" => id,
       "node" => owner,
       "outcome" => "created",
       "ready" => ready?,
       "error" => Wire.to_json(error)
     }}
  end

  def fork_reply(result), do: reply(result)

  @doc false
  # These are not refusals. Harness may already have returned a turn id, its call may
  # have exited before a trustworthy acknowledgement, or a synchronous refusal may have
  # failed to replace the durable `:dispatching` intent that recovery can still send.
  # In every case the caller-owned id is the reconciliation boundary and retrying under
  # a new id could duplicate live work.
  def turn_error_reply(
        {:turn_dispatch_checkpoint_failed, :dispatch_may_have_started, turn_id} = reason
      )
      when is_binary(turn_id) do
    unknown_turn_dispatch(turn_id, reason)
  end

  def turn_error_reply(
        {:turn_dispatch_checkpoint_failed, :dispatch_may_have_started, turn_id,
         {:harness_refused, _refusal}} = reason
      )
      when is_binary(turn_id) do
    unknown_turn_dispatch(turn_id, reason)
  end

  def turn_error_reply(
        {:turn_dispatch_checkpoint_failed, :dispatch_may_have_started, turn_id,
         {:request_exposure_failed, _failure}} = reason
      )
      when is_binary(turn_id) do
    unknown_turn_dispatch(turn_id, reason)
  end

  def turn_error_reply({:turn_dispatch_ambiguous, turn_id} = reason)
      when is_binary(turn_id) do
    unknown_turn_dispatch(turn_id, reason)
  end

  def turn_error_reply({:turn_dispatch_ambiguous, turn_id, :checkpoint_failed} = reason)
      when is_binary(turn_id) do
    unknown_turn_dispatch(turn_id, reason)
  end

  # Harness accepts `follow_up` while a session is running and queues it, but refuses a
  # second immediate `send_message` as `:busy`. Name that distinction so an interactive
  # client can preserve the draft and switch to the queueing verb instead of showing an
  # opaque upstream failure. Harness answered synchronously, so this input did not cross
  # the dispatch boundary and a retry under a fresh logical id is safe.
  def turn_error_reply({:turn_dispatch_failed, :busy} = reason) do
    {:error, code(:upstream_error),
     "the session is already running a turn; queue this input with interactive.follow_up",
     %{
       "reason" => "busy",
       "outcome" => "not_dispatched",
       "retry_with" => "interactive.follow_up",
       "error" => Wire.to_json(reason)
     }}
  end

  def turn_error_reply(reason),
    do: {:error, code(:upstream_error), "the runtime refused the call", Wire.to_json(reason)}

  defp unknown_turn_dispatch(turn_id, reason) do
    {:error, code(:upstream_timeout),
     "the runtime could not confirm the turn dispatch; the turn may already be running",
     %{
       "outcome" => "unknown",
       "turn_id" => turn_id,
       "error" => Wire.to_json(reason)
     }}
  end

  # Account failures are attributed here rather than in the shared reply mapper: these
  # shapes are also used by unrelated planes, and only these methods call OpenAI OAuth.
  def account_reply({:error, {:timeout, operation}}),
    do: {:error, code(:upstream_timeout), "OpenAI authentication timed out during #{operation}"}

  def account_reply({:error, {:upstream, message}}) when is_binary(message),
    do: upstream_error({:openai_auth, message})

  def account_reply(result), do: reply(result)

  def forget_session_owner_reply({:ok, result}), do: {:ok, result}

  def forget_session_owner_reply({:error, {:invalid_session_owner_machine, machine}}) do
    invalid_params(
      "params.machine must be the exact fleet machine name, got: #{inspect(machine)}"
    )
  end

  def forget_session_owner_reply({:error, {:session_owner_not_tombstoned, machine}}) do
    not_found(
      "fleet profile has no signed roster tombstone for machine #{inspect(machine)}; cancel it and import the updated roster before accepting state loss"
    )
  end

  def forget_session_owner_reply({:error, {:session_owner_connected, machine, owner}}) do
    {:error, code(:unavailable),
     "machine #{machine} is connected as #{owner}; inspect or copy its sessions instead of forgetting live state",
     %{
       "reason" => "session_owner_connected",
       "machine" => machine,
       "node" => owner
     }}
  end

  def forget_session_owner_reply({:error, :fleet_profile_unavailable}) do
    unavailable(
      "no active fleet profile is available; this command only retires a member already tombstoned by a signed fleet roster"
    )
  end

  def forget_session_owner_reply({:error, {:fleet_profile_unavailable, reason}}) do
    {:error, code(:unavailable),
     "the local fleet profile could not be validated; repair or re-import it before forgetting session state",
     %{"reason" => "fleet_profile_unavailable", "error" => Wire.to_json(reason)}}
  end

  def forget_session_owner_reply({:error, {:session_owner_evidence_unavailable, reason}}) do
    {:error, code(:unavailable),
     "durable session-owner evidence is unavailable; repair it before accepting state loss",
     %{"reason" => "session_owner_evidence_unavailable", "error" => Wire.to_json(reason)}}
  end

  def forget_session_owner_reply({:error, {:session_owner_forget_checkpoint_failed, reason}}) do
    {:error, code(:upstream_error),
     "session-owner evidence could not be checkpointed, so no state was forgotten",
     %{
       "reason" => "session_owner_forget_checkpoint_failed",
       "error" => Wire.to_json(reason)
     }}
  end

  def forget_session_owner_reply({:error, reason}), do: upstream_error(reason)

  def exit_result(reason) do
    case exit_class(reason) do
      :gone ->
        {:error, code(:unavailable), "that plane is not running on this node",
         Wire.to_json(reason)}

      :timeout ->
        {:error, code(:upstream_timeout), "the runtime did not answer in time",
         Wire.to_json(reason)}

      :other ->
        {:error, code(:upstream_error), "the runtime failed the call", Wire.to_json(reason)}
    end
  end

  defp exit_class(:noproc), do: :gone
  defp exit_class({:noproc, _detail}), do: :gone
  defp exit_class(:normal), do: :gone
  defp exit_class({:normal, _detail}), do: :gone
  defp exit_class(:shutdown), do: :gone
  defp exit_class({:shutdown, _detail}), do: :gone
  defp exit_class(:timeout), do: :timeout
  defp exit_class({:timeout, _detail}), do: :timeout
  defp exit_class(_reason), do: :other

  def upstream_error(reason) do
    {:error, code(:upstream_error), "the runtime failed the call", Wire.to_json(reason)}
  end

  def unavailable(message), do: {:error, code(:unavailable), message}

  def unavailable_not_dispatched(message),
    do: {:error, code(:unavailable), message, %{"outcome" => "not_dispatched"}}

  def not_found(message), do: {:error, code(:not_found), message}
  def invalid_params(message), do: {:error, code(:invalid_params), message}
end
