defmodule Ouroboros.Upgrade.Rollout.Probe do
  @moduledoc """
  The health check a capability rollout runs on every target node.

  `ready?/1` is passed to `Ouroboros.Upgrade.Coordinator.deploy/3` as
  `health_check: {__MODULE__, :ready?, [module]}` and runs, through `:erpc`, on each node
  that just committed the code. It starts the freshly introduced module as a throwaway
  mesh agent under a unique probe id, sends it one synthetic `ouroboros.agent.message`
  signal, checks the answer, and stops it again. A capability that cannot be started, or
  that will not answer a message, never becomes live anywhere: one failing node rolls the
  whole deployment back.

  ## The contract this imposes

  A capability agent must be startable by `Ouroboros.Mesh.start_agent/2` with no options
  beyond an id, and must route `ouroboros.agent.message` to something that answers. That
  is the smallest contract under which a generic probe can say anything at all about code
  it has never seen. A capability whose real work needs seeded state should still answer
  a bare message; the probe is a liveness check, not an acceptance test.

  ## Why every path is defended

  The coordinator reads two very different failures from a health check. A *result* it
  does not consider healthy is a clean failure: every committed node is rolled back and
  the deployment reports `:health_failed` with `recovery: :complete`. A *transport*
  failure — which is what an uncaught exception inside this function becomes once `:erpc`
  is done with it — is ambiguity, and ambiguity is not something a probe should ever
  manufacture about itself. So every clause here converts exceptions, exits, and throws
  into `{:error, reason}`, including the ones in the cleanup path, and the return value
  is always a plain serializable term: `:ok` or `{:error, term}`, never a pid, struct, or
  reference crossing back over the wire.
  """

  alias Ouroboros.Mesh

  @probe_source "ouroboros-rollout-probe"
  @call_timeout 5_000
  @visibility_retries 20
  @visibility_delay_ms 25

  @doc "Starts, messages, and stops one throwaway instance of `module` on this node."
  @spec ready?(module()) :: :ok | {:error, term()}
  def ready?(module) when is_atom(module) and not is_nil(module) do
    id = probe_id(module)

    try do
      probe(id, module)
    rescue
      error -> {:error, {:probe_exception, module, Exception.message(error)}}
    catch
      kind, reason -> {:error, {:probe_failure, module, kind, inspect(reason)}}
    after
      stop(id)
    end
  end

  def ready?(module), do: {:error, {:invalid_probe_module, inspect(module)}}

  defp probe(id, module) do
    body = %{probe: id, node: node()}

    with :ok <- ensure_loaded(module),
         {:ok, _pid} <- start(id, module),
         :ok <- await_visible(id, @visibility_retries),
         {:ok, agent} <- exchange(id, body),
         :ok <- sane_reply?(agent, body) do
      :ok
    else
      {:error, reason} -> {:error, {:probe_failed, module, sanitize(reason)}}
      other -> {:error, {:probe_failed, module, {:unexpected_result, inspect(other)}}}
    end
  end

  # The module is supposed to have been loaded by the commit that just happened. Asking
  # first turns "the rollout loaded nothing" into a named failure instead of an
  # `UndefinedFunctionError` raised from inside an agent's start.
  defp ensure_loaded(module) do
    case Code.ensure_loaded(module) do
      {:module, ^module} -> :ok
      {:error, reason} -> {:error, {:capability_not_loaded, reason}}
    end
  end

  defp start(id, module) do
    case Mesh.start_agent(id, agent: module) do
      {:ok, pid} -> {:ok, pid}
      {:error, reason} -> {:error, {:probe_start_failed, reason}}
      other -> {:error, {:probe_start_failed, {:unexpected_result, inspect(other)}}}
    end
  end

  # Mesh visibility is eventually consistent even for a local agent, so a probe that
  # asked once could report a healthy capability as missing.
  defp await_visible(_id, 0), do: {:error, :probe_agent_not_visible}

  defp await_visible(id, attempts) do
    if is_pid(Mesh.whereis(id)) do
      :ok
    else
      Process.sleep(@visibility_delay_ms)
      await_visible(id, attempts - 1)
    end
  end

  defp exchange(id, body) do
    case Mesh.send_message(@probe_source, id, body, timeout: @call_timeout) do
      {:ok, agent} -> {:ok, agent}
      {:error, reason} -> {:error, {:probe_message_failed, reason}}
      other -> {:error, {:probe_message_failed, {:unexpected_result, inspect(other)}}}
    end
  end

  # The floor is an agent that survived the signal and still has inspectable state. If it
  # keeps a `:last_message` the way `Ouroboros.Agent.Worker` does, that message must be
  # the one just sent — an agent that answers while ignoring its input is not ready.
  defp sane_reply?(agent, body) do
    state = if is_struct(agent), do: Map.get(agent, :state), else: nil

    cond do
      not is_map(state) -> {:error, {:probe_reply_invalid, inspect(agent)}}
      not Map.has_key?(state, :last_message) -> :ok
      echoed?(Map.get(state, :last_message), body) -> :ok
      true -> {:error, {:probe_reply_not_echoed, inspect(Map.get(state, :last_message))}}
    end
  end

  defp echoed?(%{body: body}, body), do: true
  defp echoed?(_message, _body), do: false

  defp stop(id) do
    Mesh.stop_agent(id)
    :ok
  rescue
    _error -> :ok
  catch
    _kind, _reason -> :ok
  end

  defp probe_id(module) do
    "ouroboros-probe-" <>
      (module |> Atom.to_string() |> String.replace(".", "-")) <>
      "-" <> Integer.to_string(System.unique_integer([:positive]))
  end

  # This value is returned across `:erpc` into a coordinator that stores it in a
  # deployment receipt, so anything whose shape is not guaranteed becomes text.
  defp sanitize(reason) do
    if serializable?(reason), do: reason, else: inspect(reason)
  end

  defp serializable?(term) when is_atom(term) or is_binary(term) or is_number(term), do: true
  defp serializable?(term) when is_list(term), do: Enum.all?(term, &serializable?/1)

  defp serializable?(term) when is_tuple(term),
    do: term |> Tuple.to_list() |> Enum.all?(&serializable?/1)

  defp serializable?(term) when is_map(term) do
    not is_struct(term) and
      Enum.all?(term, fn {key, value} -> serializable?(key) and serializable?(value) end)
  end

  defp serializable?(_term), do: false
end
