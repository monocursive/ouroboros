defmodule Ouroboros.Provider.Native.Permissions do
  @moduledoc """
  The one call the native loop makes into the permission engine, and the only thing it
  knows about whether that engine exists.

  `Ouroboros.Control.Permissions` (slice C1, D5) is being built in parallel. Rather than
  couple the loop to a module that may or may not be compiled, the loop asks here and
  gets one of three answers. When the engine is absent every request answers
  `{:ask, :no_engine}` — the fail-closed direction: a missing rule engine turns into a
  human question, never into a silent allow.

  The engine's contract, checked at call time with `Code.ensure_loaded?/1` and
  `function_exported?/3` so a partial or older module cannot crash a turn:

      evaluate(%{
        principal: %{session_id: String.t(), provider: :native, node: node()},
        tool: String.t(),
        command: String.t() | nil,
        paths: [String.t()],
        mode: :read | :write | :execute | :network,
        domains: [String.t()],
        context: map()
      }) :: {:allow, rule_ref} | {:deny, rule_ref} | {:ask, reason}

      record(decision_id, %{
        decision: :approve | :deny,
        scope: :once | :session | :always,
        actor: :rule | :human,
        rule_ref: term() | nil,
        reason: String.t() | nil
      }) :: :ok | {:error, term()}

  A return this module does not recognise is treated as `{:ask, {:engine_error, …}}`.
  An engine that returns nonsense must not be able to authorize anything.
  """

  @engine Ouroboros.Control.Permissions

  @type decision :: {:allow, term()} | {:deny, term()} | {:ask, term()}

  @doc "Evaluates one tool attempt. `{:ask, :no_engine}` when no engine is loaded."
  @spec evaluate(map()) :: decision()
  def evaluate(request) when is_map(request) do
    if exported?(:evaluate, 1) do
      case apply(@engine, :evaluate, [request]) do
        {:allow, _rule} = decision -> decision
        {:deny, _rule} = decision -> decision
        {:ask, _reason} = decision -> decision
        other -> {:ask, {:engine_error, inspect(other)}}
      end
    else
      {:ask, :no_engine}
    end
  rescue
    error -> {:ask, {:engine_error, Exception.message(error)}}
  catch
    :exit, reason -> {:ask, {:engine_error, inspect(reason)}}
  end

  @doc """
  Records a resolved decision in the engine's ledger.

  `{:error, :no_engine}` when there is nothing to record into. The loop keeps going: an
  unrecorded decision is a gap in the audit trail, not a reason to refuse work the
  operator already approved — and the session's own events still carry
  `approval_requested`/`approval_resolved`.
  """
  @spec record(String.t(), map()) :: :ok | {:error, term()}
  def record(decision_id, attrs) when is_binary(decision_id) and is_map(attrs) do
    if exported?(:record, 2) do
      case apply(@engine, :record, [decision_id, attrs]) do
        :ok -> :ok
        {:error, _reason} = error -> error
        other -> {:error, {:engine_error, inspect(other)}}
      end
    else
      {:error, :no_engine}
    end
  rescue
    error -> {:error, {:engine_error, Exception.message(error)}}
  catch
    :exit, reason -> {:error, {:engine_error, inspect(reason)}}
  end

  @doc "Whether a rule engine is available on this node."
  @spec engine?() :: boolean()
  def engine?, do: exported?(:evaluate, 1)

  @doc "How a refusal reads in a tool result. Names the rule, never invents one."
  @spec deny_message(String.t(), term()) :: String.t()
  def deny_message(tool, rule_ref) do
    "Refused: permission rule #{format_rule(rule_ref)} denies #{tool} for this session."
  end

  @doc "The rule a human approval would create, offered alongside the ask."
  @spec suggested_rule(String.t(), String.t() | nil, [String.t()]) :: map()
  def suggested_rule(tool, command, paths) do
    %{"tool" => tool}
    |> maybe_put("command_prefix", command_prefix(command))
    |> maybe_put("paths", if(paths == [], do: nil, else: paths))
  end

  defp command_prefix(nil), do: nil

  defp command_prefix(command) when is_binary(command) do
    case command |> String.trim() |> String.split(~r/\s+/, parts: 2) do
      [head | _rest] when head != "" -> head
      _empty -> nil
    end
  end

  defp command_prefix(_command), do: nil

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp format_rule(nil), do: "(unnamed)"
  defp format_rule(rule) when is_binary(rule), do: rule
  defp format_rule(rule), do: inspect(rule)

  defp exported?(function, arity) do
    Code.ensure_loaded?(@engine) and function_exported?(@engine, function, arity)
  end
end
