defmodule Ouroboros.Control.Permissions.Engine do
  @moduledoc """
  Typed, fail-closed access to the configured permission engine. Unknown answers and
  unavailable engines ask; audit recording is returned separately from admission.
  """
  @type decision :: {:allow, term()} | {:deny, term()} | {:ask, term()}
  defp engine,
    do: Application.get_env(:ouroboros, :permissions_engine, Ouroboros.Control.Permissions)

  def evaluate(request) do
    if exported?(:evaluate, 1) do
      case apply(engine(), :evaluate, [request]) do
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

  def record(decision_id, attrs) when is_binary(decision_id) and is_map(attrs) do
    if exported?(:record, 2) do
      case apply(engine(), :record, [decision_id, attrs]) do
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

  def suggest(request) when is_map(request) do
    if exported?(:suggest, 1) do
      case apply(engine(), :suggest, [request]) do
        pattern when is_binary(pattern) and pattern != "" -> pattern
        _nothing_to_suggest -> nil
      end
    end
  rescue
    _error -> nil
  catch
    :exit, _reason -> nil
  end

  def exported?(function, arity) do
    engine = engine()

    is_atom(engine) and not is_nil(engine) and Code.ensure_loaded?(engine) and
      function_exported?(engine, function, arity)
  end
end
