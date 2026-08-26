defmodule Ouroboros.Interactive.Task.Shell do
  @moduledoc false

  require Logger

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Interactive.State
  alias Ouroboros.Interactive.Task
  alias Ouroboros.Interactive.Task.Approvals
  alias Ouroboros.Runtime.Exposure
  alias Ouroboros.Workspace.Exec

  # B7. A command line an operator typed, bounded where it is accepted. The permission
  # engine bounds its own reading at 8 KiB; anything past this is not a command somebody
  # meant to run in a terminal.
  @max_shell_command_bytes 8_192

  # How many of an operator's own commands the next turn's runtime envelope carries.
  # Three, and only their excerpts: the model is being told what the person just did, not
  # given a second transcript to read.
  @max_exposed_operator_commands 3

  def plan(runtime, command, caller) do
    session = runtime.session

    cond do
      State.terminal?(session) ->
        {:error, {:session_not_executable, %{status: session.status}}, runtime}

      not is_binary(command) or String.trim(command) == "" ->
        {:error, {:invalid_shell_command, %{reason: :blank}}, runtime}

      byte_size(command) > @max_shell_command_bytes ->
        {:error, {:invalid_shell_command, %{reason: :too_long, limit: @max_shell_command_bytes}},
         runtime}

      true ->
        case shell_authority(runtime, command) do
          {:ok, authority} -> open_operator_shell(runtime, command, authority, caller)
          {:error, reason} -> {:error, reason, runtime}
        end
    end
  end

  def settle(runtime, effect_id, outcome) do
    _ = Task.safe_ledger(fn -> EffectLedger.settle(effect_id, settlement(outcome)) end)

    case Task.emit_runtime_event(
           runtime,
           :provider_event,
           shell_event_payload(effect_id, outcome),
           provider: runtime.session.provider,
           harness_session_id: runtime.session.harness_session_id,
           provider_session_id: runtime.session.provider_session_id
         ) do
      {:ok, runtime} ->
        refresh_operator_exposure(runtime)

      {:error, runtime} ->
        Logger.warning(
          "interactive session #{runtime.session.id} ran an operator command but could " <>
            "not append it to the transcript; the ledger entry #{effect_id} stands"
        )

        runtime
    end
  end

  defp shell_authority(runtime, command) do
    session = runtime.session

    if Map.get(session.options, :approval_mode) == :auto_approve do
      {:ok, %{reason: :auto_approve, rule: nil}}
    else
      case evaluate_shell_permission(runtime, command) do
        {:allow, rule} -> {:ok, %{reason: :rule, rule: rule}}
        {:deny, rule} -> {:error, shell_refused(runtime, command, :rule_denied, rule)}
        {:ask, reason} -> {:error, shell_refused(runtime, command, reason, nil)}
      end
    end
  end

  defp shell_request(%State{} = session, command) do
    %{
      principal: %{session_id: session.id, provider: session.provider, node: node()},
      tool: "bash",
      command: command,
      mode: :execute,
      context: %{workspace: session.workspace}
    }
  end

  defp evaluate_shell_permission(runtime, command) do
    case Approvals.permissions_engine(:evaluate, 1) do
      nil ->
        {:ask, :no_permission_engine}

      engine ->
        case apply(engine, :evaluate, [shell_request(runtime.session, command)]) do
          {:allow, rule} -> {:allow, rule}
          {:deny, rule} -> {:deny, rule}
          {:ask, reason} -> {:ask, reason}
          _unrecognised -> {:ask, :engine_answer_unrecognised}
        end
    end
  rescue
    exception -> {:ask, {:engine_failed, Exception.message(exception)}}
  catch
    :exit, _reason -> {:ask, :engine_unavailable}
  end

  defp shell_refused(runtime, command, reason, rule) do
    session = runtime.session

    {:shell_refused,
     %{
       reason: shell_reason(reason),
       session_id: session.id,
       workspace: session.workspace,
       approval_mode: Map.get(session.options, :approval_mode),
       denied_by: rule_reference(rule),
       suggested_rule: shell_suggestion(session, command),
       message: shell_refusal_message(reason)
     }}
  end

  defp shell_reason(reason) when is_atom(reason), do: reason
  defp shell_reason({tag, _detail}) when is_atom(tag), do: tag
  defp shell_reason(_reason), do: :not_permitted

  defp rule_reference(%{scope: scope, id: id, pattern: pattern}),
    do: %{scope: scope, id: id, pattern: pattern}

  defp rule_reference(_rule), do: nil

  defp shell_suggestion(session, command) do
    case Approvals.permissions_engine(:suggest, 1) do
      nil ->
        nil

      engine ->
        case apply(engine, :suggest, [shell_request(session, command)]) do
          rule when is_binary(rule) and rule != "" -> rule
          _nothing_to_suggest -> nil
        end
    end
  rescue
    _exception -> nil
  catch
    :exit, _reason -> nil
  end

  defp shell_refusal_message(:rule_denied),
    do:
      "a permission rule denies this command. A deny beats every allow at every scope, " <>
        "so remove that rule with permissions.remove before adding another."

  defp shell_refusal_message(_reason),
    do:
      "workspace.exec runs a command as your own act, so it needs the session to be at " <>
        "approval_mode auto_approve or a permission rule that allows it. Add the " <>
        "suggested rule with permissions.add, or move the session with " <>
        "interactive.configure."

  defp open_operator_shell(runtime, command, authority, caller) do
    session = runtime.session
    effect_id = operator_shell_id(session.id, command)

    attrs = %{
      id: effect_id,
      effect: :operator_shell,
      principal: "session:" <> session.id,
      attempt: %{
        session_id: session.id,
        command_digest: Exec.digest(command),
        cwd: session.workspace,
        node: node(),
        rule_id: authority.rule && Map.get(authority.rule, :id)
      },
      authority: %{
        decision: :allow,
        reason: Atom.to_string(authority.reason),
        constraints: rule_reference(authority.rule)
      },
      cause: %{signal_type: "workspace.exec", signal_id: effect_id}
    }

    case Task.safe_ledger(fn -> EffectLedger.record_started(attrs) end) do
      {:ok, _entry, _created} ->
        watch_caller(session, effect_id, caller)

        {:ok,
         %{
           effect_id: effect_id,
           command_digest: attrs.attempt.command_digest,
           cwd: session.workspace,
           spill_dir: shell_spill_dir(session.id),
           timeout_ms: Exec.timeout_ms(),
           authority: authority.reason,
           rule: rule_reference(authority.rule)
         }, runtime}

      other ->
        {:error,
         {:shell_unrecordable,
          %{
            reason: :effect_ledger_unavailable,
            detail: Task.durable(other),
            message:
              "the effect ledger could not record this command before it ran, and a " <>
                "command nobody can account for afterwards does not run."
          }}, runtime}
    end
  end

  # The command runs in the caller's own process, so the caller is this effect's runner:
  # if it dies between the plan and the settlement, nobody else is going to say so. The
  # ledger learns that here rather than at the next boot's reconciliation.
  defp watch_caller(session, effect_id, caller) when is_pid(caller) do
    case Task.safe_ledger(fn -> EffectLedger.watch_runner(effect_id, caller) end) do
      :ok ->
        :ok

      other ->
        Logger.warning(
          "interactive session #{session.id} could not watch the runner of operator " <>
            "command #{effect_id}: #{inspect(other, limit: 4)}; an abandoned entry will " <>
            "stay :started until the next boot reconciles it"
        )
    end
  end

  defp watch_caller(_session, _effect_id, _caller), do: :ok

  defp shell_spill_dir(session_id) do
    case Exec.spill_dir(session_id) do
      {:ok, path} -> path
      {:error, _reason} -> nil
    end
  end

  defp operator_shell_id(session_id, command) do
    digest =
      :sha256
      |> :crypto.hash(
        :erlang.term_to_binary(
          {node(), session_id, Exec.digest(command), System.system_time(:nanosecond),
           System.unique_integer([:positive, :monotonic])}
        )
      )
      |> Base.encode16(case: :lower)

    "shell-" <> binary_slice(digest, 0, 32)
  end

  defp settlement(%{exit_status: status, timed_out: timed_out?} = result) do
    %{
      status: if(status == 0 and not timed_out?, do: :ok, else: :failed),
      result: %{
        exit_status: status,
        duration_ms: Map.get(result, :duration_ms),
        output_bytes: Map.get(result, :output_bytes),
        spilled: not is_nil(Map.get(result, :spilled)),
        timed_out: timed_out?
      }
    }
  end

  defp settlement(%{error: reason}), do: %{status: :failed, error: Task.durable(reason)}

  defp shell_event_payload(effect_id, %{exit_status: _status} = result) do
    %{
      "kind" => "operator_shell",
      "effect_id" => effect_id,
      "command_digest" => Map.get(result, :command_digest),
      "exit_status" => Map.get(result, :exit_status),
      "duration_ms" => Map.get(result, :duration_ms),
      "timed_out" => Map.get(result, :timed_out),
      "output_bytes" => Map.get(result, :output_bytes),
      "output_excerpt" => Map.get(result, :excerpt)
    }
    |> put_present("spilled", Map.get(result, :spilled))
  end

  defp shell_event_payload(effect_id, %{error: reason}) do
    %{
      "kind" => "operator_shell",
      "effect_id" => effect_id,
      "exit_status" => nil,
      "output_excerpt" => "",
      "error" => inspect(reason, limit: 6)
    }
  end

  defp refresh_operator_exposure(runtime) do
    session = runtime.session

    if Map.get(session.options, :runtime_exposure, true) do
      capture =
        Exposure.capture(
          sandbox_mode: Map.get(session.options, :sandbox_mode),
          operator_shell: recent_operator_commands(session)
        )

      updated = session |> Map.put(:runtime_snapshot, capture) |> State.touch()

      case Task.persist(runtime, updated, []) do
        {:ok, runtime} ->
          runtime

        {:error, runtime} ->
          Logger.warning(
            "interactive session #{session.id} could not refresh its runtime exposure " <>
              "after an operator command; the next turn carries the previous envelope"
          )

          runtime
      end
    else
      runtime
    end
  end

  defp recent_operator_commands(session) do
    session.events
    |> Enum.filter(
      &(&1.type == :provider_event and Map.get(&1.payload, "kind") == "operator_shell")
    )
    |> Enum.take(-@max_exposed_operator_commands)
    |> Enum.map(
      &%{
        command_digest: Map.get(&1.payload, "command_digest"),
        exit_status: Map.get(&1.payload, "exit_status"),
        excerpt: Map.get(&1.payload, "output_excerpt")
      }
    )
  end

  defp put_present(map, _key, nil), do: map
  defp put_present(map, _key, ""), do: map
  defp put_present(map, key, value), do: Map.put(map, key, value)
end
