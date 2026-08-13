defmodule Ouroboros.Agent.Effects.Runner do
  @moduledoc """
  The one path every agent effect takes: identify, authorize, bound, record.

  An effect action never touches `Ouroboros.Mesh`, `Ouroboros.Team`, or the forge
  directly. It builds the concrete attempt it wants to make and a zero-arity closure that
  would make it, and hands both here. This module then does the four things that must
  happen the same way for every effect:

  1. **Identify the actor from server-side state.** The principal is `context.agent.id` —
     the identity `Ouroboros.Mesh.start_agent/2` gave this process, read from the agent
     struct the agent server owns. Jido drops `:agent`, `:state`, `:signal`, and
     `:agent_server_pid` from any caller-supplied action context before merging it, so
     this field cannot be supplied by whoever sent the signal. The `from` field the
     signal carries is recorded beside it as `claimed_from` and is never used to
     authorize anything.
  2. **Authorize the concrete attempt.** `Ouroboros.Control.Grants.granted?/3` is asked
     about this module, this team, these nodes — not about the effect in the abstract. A
     refusal returns `{:error, {:effect_denied, effect, reason}}`, which Jido turns into
     an error directive: the agent logs it and stays alive.
  3. **Bound the work.** The closure runs in a supervised task, off the agent's own
     process, under `config :ouroboros, :effect_timeout` (120s by default). A forge that
     boots a build peer, compiles, and runs a capability's tests takes far longer than
     the agent server should ever sit still, and far longer than Jido's own action
     deadline. A closure that outlives its budget is killed and recorded as a timeout.
  4. **Record what happened.** The requesting action returns immediately with a
     `:started` entry in `last_effects` and an in-flight registration. When the runner
     finishes it sends `Ouroboros.Signals.EffectSettled` back, and `RecordEffect` folds
     the outcome into the same entry. Refusals never start a runner, so they arrive as a
     record of their own.

  ## What a settle signal can and cannot do

  The settle signal is a completion channel, not an authority. Anyone who can reach an
  agent can send one, so it is scoped to what a forged completion could not abuse:
  settling an effect requires an `effect_id` this agent minted and still has in flight,
  and only that path can add a forged artifact to `state.forged`. A refusal record needs
  no in-flight entry, so a spoofed one can add a line to the audit trail — and nothing
  else. No settle signal can grant, start, message, forge, or deploy anything, because
  the authority decision happened before the effect ran.
  """

  alias Ouroboros.Control.Grants
  alias Ouroboros.Mesh
  alias Ouroboros.Signals.EffectSettled

  @default_timeout 120_000
  @trail_limit 20
  @forged_limit 5
  @settle_timeout 5_000
  @settle_retries 40
  @settle_retry_ms 25

  @type effect :: atom()
  @type attempt :: %{optional(atom()) => term()}
  @type outcome :: {:ok, map()} | {:error, term()}

  @doc """
  Authorizes one attempt and, if it is permitted, starts it under a bounded runner.

  Returns the state projection the calling action should return, or a typed refusal.
  """
  @spec dispatch(effect(), attempt(), (String.t() -> outcome()), map(), map()) ::
          {:ok, map()} | {:error, term()}
  def dispatch(effect, attempt, run, params, context) when is_function(run, 1) do
    with {:ok, principal} <- principal(context, effect),
         {:ok, state} <- effect_state(context, effect) do
      server = server(principal, state)

      if Grants.granted?(principal, effect, attempt) do
        accept(effect, attempt, run, principal, params, state, server)
      else
        refuse(effect, attempt, principal, params, context, server)
      end
    end
  end

  @doc "Folds a settled outcome into the acting agent's audit trail."
  @spec settle(map(), map()) :: {:ok, map()} | {:error, term()}
  def settle(agent_state, %{effect_id: effect_id, status: :denied} = params) do
    if Enum.any?(agent_state.last_effects, &(&1.id == effect_id)) do
      {:ok, %{}}
    else
      {:ok, %{last_effects: push(agent_state.last_effects, denied_entry(params))}}
    end
  end

  def settle(agent_state, %{effect_id: effect_id} = params) do
    case Enum.find(agent_state.effects_in_flight, &(&1.id == effect_id)) do
      nil ->
        {:error, {:unknown_effect, effect_id}}

      entry ->
        settled = settled_entry(entry, params)

        {:ok,
         %{
           effects_in_flight: Enum.reject(agent_state.effects_in_flight, &(&1.id == effect_id)),
           last_effects: replace(agent_state.last_effects, settled),
           forged: remember(agent_state.forged, params)
         }}
    end
  end

  @doc """
  The deadline one effect may take, from `config :ouroboros, :effect_timeout`.

  `:infinity` is deliberately not accepted. The point of this budget is that an effect
  cannot outlive it, so an unusable value falls back to the default rather than removing
  the bound.
  """
  @spec timeout() :: pos_integer()
  def timeout do
    case Application.get_env(:ouroboros, :effect_timeout, @default_timeout) do
      value when is_integer(value) and value > 0 -> value
      _invalid -> @default_timeout
    end
  end

  # The identity comes from the agent struct the server owns. An agent started without
  # one has no principal, and an effect surface with no principal authorizes nothing.
  defp principal(%{agent: %{id: id}}, _effect) when is_binary(id) and id != "", do: {:ok, id}

  defp principal(_context, effect),
    do: {:error, {:effect_denied, effect, :unidentified_principal}}

  # The trail lives in agent state, so an agent whose schema has no room for it cannot
  # run effects at all rather than running them unrecorded.
  defp effect_state(%{agent: %{state: state}}, effect) when is_map(state) do
    if Map.has_key?(state, :last_effects) and Map.has_key?(state, :effects_in_flight) and
         Map.has_key?(state, :forged) do
      {:ok, state}
    else
      {:error, {:effect_denied, effect, :missing_effect_state}}
    end
  end

  defp effect_state(_context, effect),
    do: {:error, {:effect_denied, effect, :missing_agent_state}}

  # `context.agent_server_pid` is the process that ran this action, which for a signal
  # call is a short-lived task rather than the agent server. The agent's own registries
  # are the only reliable route back: the Jido instance registry answers for this node,
  # and the mesh directory covers an agent registered there but not here.
  defp server(principal, state) do
    Ouroboros.Jido.whereis(principal, partition: Map.get(state, :__partition__)) ||
      Mesh.whereis(principal)
  end

  defp accept(effect, attempt, run, principal, params, state, server) do
    effect_id = Jido.Signal.ID.generate!()
    entry = started_entry(effect_id, effect, attempt, principal, params)

    case start_runner(effect_id, effect, fn -> run.(principal) end, server) do
      {:ok, _pid} ->
        {:ok,
         %{
           effects_in_flight: Enum.take([entry | state.effects_in_flight], @trail_limit),
           last_effects: push(state.last_effects, entry)
         }}

      {:error, reason} ->
        {:error, {:effect_failed, effect, {:runner_unavailable, reason}}}
    end
  end

  defp refuse(effect, attempt, principal, params, context, server) do
    reason = {:not_granted, attempt}

    # This runs *inside* the agent's in-flight signal call, so the refusal record is cast
    # rather than called: a nested call would queue behind the very call it is inside.
    # Nothing about a refusal depends on ordering — it settles no in-flight entry.
    cast(server, %{
      effect_id: refusal_id(context),
      effect: effect,
      status: :denied,
      principal: principal,
      claimed_from: claimed_from(params),
      attempt: attempt,
      error: {:effect_denied, effect, reason}
    })

    {:error, {:effect_denied, effect, reason}}
  end

  # Jido retries an action that returns an error, so a refusal is identified by the
  # signal it refused. One refused request leaves one line, however many times the
  # runtime asks the same question.
  defp refusal_id(%{signal: %{id: id}}) when is_binary(id) and id != "", do: "refused-" <> id
  defp refusal_id(_context), do: Jido.Signal.ID.generate!()

  # Two processes, on purpose. The outer one owns the deadline and the settlement and
  # cannot be taken down by the effect; the inner one does the work and is killed if it
  # runs past the budget. An in-flight entry that never settles is a lie the trail would
  # keep telling, so every path out of the outer process delivers something.
  defp start_runner(effect_id, effect, run, server) do
    supervisor = Ouroboros.Jido.task_supervisor_name()

    Task.Supervisor.start_child(supervisor, fn ->
      outcome = bounded(supervisor, run, timeout())
      deliver(server, settlement(effect_id, effect, outcome))
    end)
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  defp bounded(supervisor, run, timeout) do
    task = Task.Supervisor.async_nolink(supervisor, run)

    case Task.yield(task, timeout) || Task.shutdown(task, :brutal_kill) do
      {:ok, {:ok, result}} -> {:ok, result}
      {:ok, {:error, reason}} -> {:error, reason}
      {:ok, other} -> {:error, {:invalid_effect_result, inspect(other)}}
      {:exit, reason} -> {:error, {:effect_crashed, inspect(reason)}}
      nil -> {:error, {:effect_timeout, timeout}}
    end
  rescue
    error -> {:error, {:effect_crashed, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:effect_crashed, {kind, inspect(reason)}}}
  end

  defp settlement(effect_id, effect, {:ok, result}) do
    %{effect_id: effect_id, effect: effect, status: :ok, result: result}
  end

  defp settlement(effect_id, effect, {:error, reason}) do
    %{
      effect_id: effect_id,
      effect: effect,
      status: :failed,
      error: {:effect_failed, effect, reason}
    }
  end

  # An outcome could otherwise beat the record it settles: the in-flight registration is
  # written by the action's *return value*, which the agent server applies only after the
  # action returns and the runner is already going. Delivering the outcome as a call is
  # what orders them — a call that arrives while the requesting call is still in flight
  # is queued behind it, so the registration is always applied first. The reply says
  # whether the entry took, and the bounded retry covers the remaining case: an agent
  # that was mid-restart and has not read the request yet.
  #
  # A settle that cannot be delivered at all loses an audit line for an agent that is
  # already gone. It must never take the runner, or the effect's caller, down with it.
  defp deliver(server, attrs, attempts \\ @settle_retries)

  defp deliver(server, attrs, attempts) when is_pid(server) do
    with {:ok, signal} <- EffectSettled.new(attrs, subject: attrs.effect_id),
         {:ok, agent} <- Jido.AgentServer.call(server, signal, @settle_timeout) do
      cond do
        recorded?(agent, attrs) ->
          :ok

        attempts > 0 ->
          Process.sleep(@settle_retry_ms)
          deliver(server, attrs, attempts - 1)

        true ->
          :ok
      end
    else
      _other -> :ok
    end
  catch
    _kind, _reason -> :ok
  end

  defp deliver(_server, _attrs, _attempts), do: :ok

  defp recorded?(%{state: %{last_effects: trail}}, %{effect_id: effect_id}) do
    Enum.any?(trail, &(&1.id == effect_id and &1.status != :started))
  end

  defp recorded?(_agent, _attrs), do: true

  defp cast(server, attrs) when is_pid(server) do
    case EffectSettled.new(attrs, subject: attrs.effect_id) do
      {:ok, signal} -> Jido.AgentServer.cast(server, signal)
      {:error, _reason} -> :ok
    end
  catch
    _kind, _reason -> :ok
  end

  defp cast(_server, _attrs), do: :ok

  defp started_entry(effect_id, effect, attempt, principal, params) do
    %{
      id: effect_id,
      effect: effect,
      principal: principal,
      claimed_from: claimed_from(params),
      attempt: attempt,
      status: :started,
      result: nil,
      error: nil,
      started_at: now(),
      settled_at: nil
    }
  end

  defp denied_entry(params) do
    %{
      id: params.effect_id,
      effect: params.effect,
      principal: params.principal,
      claimed_from: params.claimed_from,
      attempt: params.attempt,
      status: :denied,
      result: nil,
      error: params.error,
      started_at: now(),
      settled_at: now()
    }
  end

  # The trail keeps a summary, not the payload. A forged artifact carries a BEAM binary
  # and belongs in `state.forged` exactly once, keyed by the id a deploy will name.
  defp settled_entry(entry, params) do
    %{
      entry
      | status: params.status,
        result: summarize(params.result),
        error: params.error,
        settled_at: now()
    }
  end

  defp summarize(result) when is_map(result) and not is_struct(result),
    do: Map.drop(result, [:artifact])

  defp summarize(result), do: result

  # Each remembered artifact carries a BEAM binary, so this ring is much shorter than the
  # audit trail: an agent keeps what it can still deploy, not everything it ever built.
  defp remember(forged, %{status: :ok, result: %{artifact: artifact, module: module}}) do
    entry = %{
      artifact_id: artifact.id,
      artifact: artifact,
      module: module,
      epoch: artifact.epoch,
      forged_at: now()
    }

    Enum.take([entry | Enum.reject(forged, &(&1.artifact_id == artifact.id))], @forged_limit)
  end

  defp remember(forged, _params), do: forged

  defp push(trail, entry), do: Enum.take([entry | trail], @trail_limit)

  # An entry that has already been pushed out of the ring is not resurrected: the ring is
  # the bound, and a slow effect that outlived its own record settles into nothing.
  defp replace(trail, entry) do
    Enum.map(trail, fn
      %{id: id} when id == entry.id -> entry
      other -> other
    end)
  end

  defp claimed_from(params), do: Map.get(params, :from)

  defp now, do: DateTime.utc_now() |> DateTime.to_iso8601()
end
