defmodule Ouroboros.Provider.Native.Cost do
  @moduledoc """
  Turns a model response's token counts into a `usage` payload with numbers in it.

  Pricing comes from `llm_db`'s per-million-token rates for the resolved model. When
  the model is unknown to `llm_db`, or its entry carries no rates, `cost_usd` is absent
  from the payload — it is not zero. A zero would render in the footer as a free turn,
  and "we do not know what this cost" is a different fact from "this cost nothing".

  The payload is numbers and strings only. No provider response, no request, no key.
  """

  @doc """
  Normalizes one usage map into the payload shape every consumer already reads.

  Accepts whatever key spelling a provider used — `input_tokens`/`input`/`prompt_tokens`
  and the cache variants — and emits string keys with integer values.
  """
  @spec payload(map(), String.t() | nil) :: map()
  def payload(usage, model_spec) when is_map(usage) do
    input = count(usage, [:input_tokens, :input, :prompt_tokens])
    output = count(usage, [:output_tokens, :output, :completion_tokens])
    cache_read = count(usage, [:cache_read_tokens, :cached_tokens, :cache_read_input_tokens])

    cache_creation =
      count(usage, [:cache_creation_tokens, :cache_write_tokens, :cache_creation_input_tokens])

    reasoning = count(usage, [:reasoning_tokens])

    total =
      case count(usage, [:total_tokens]) do
        0 -> input + output
        value -> value
      end

    base = %{
      "input_tokens" => input,
      "output_tokens" => output,
      "total_tokens" => total,
      "cache_read_tokens" => cache_read,
      "cache_creation_tokens" => cache_creation,
      "reasoning_tokens" => reasoning
    }

    base = if model_spec, do: Map.put(base, "model", model_spec), else: base

    case cost_usd(model_spec, input, output, cache_read, cache_creation) do
      nil -> base
      cost -> Map.put(base, "cost_usd", cost)
    end
  end

  def payload(_usage, model_spec), do: payload(%{}, model_spec)

  @doc """
  The dollar cost of one response, or `nil` when this node cannot price it.

  Rates in `llm_db` are per million tokens. Cached reads and cache writes are priced
  separately where the entry declares them; a cache read priced as an ordinary input
  token would overstate every turn of a long session.
  """
  @spec cost_usd(
          String.t() | nil,
          non_neg_integer(),
          non_neg_integer(),
          non_neg_integer(),
          non_neg_integer()
        ) ::
          float() | nil
  def cost_usd(nil, _input, _output, _cache_read, _cache_creation), do: nil

  def cost_usd(model_spec, input, output, cache_read, cache_creation) do
    case rates(model_spec) do
      nil ->
        nil

      rates ->
        # Providers that report cached reads count them inside the input total. Charging
        # the cached share at the cheap rate requires removing it from the full-price
        # share first, and never letting that subtraction go negative.
        billed_input = max(input - cache_read - cache_creation, 0)

        total =
          per_million(billed_input, rates[:input]) +
            per_million(output, rates[:output]) +
            per_million(cache_read, rates[:cache_read] || rates[:input]) +
            per_million(cache_creation, rates[:cache_write] || rates[:input])

        Float.round(total, 6)
    end
  end

  defp per_million(_tokens, nil), do: 0.0
  defp per_million(0, _rate), do: 0.0
  defp per_million(tokens, rate) when is_number(rate), do: tokens * rate / 1_000_000
  defp per_million(_tokens, _rate), do: 0.0

  defp rates(model_spec) do
    with true <- Code.ensure_loaded?(LLMDB),
         {:ok, model} <- LLMDB.model(model_spec),
         cost when is_map(cost) <- Map.get(model, :cost) do
      rates = Map.take(cost, [:input, :output, :cache_read, :cache_write])
      if Enum.any?(rates, fn {_key, value} -> is_number(value) end), do: rates, else: nil
    else
      _unpriced -> nil
    end
  rescue
    _error -> nil
  catch
    :exit, _reason -> nil
  end

  defp count(usage, keys) do
    Enum.find_value(keys, 0, fn key ->
      case Map.get(usage, key) || Map.get(usage, Atom.to_string(key)) do
        value when is_integer(value) and value >= 0 -> value
        value when is_float(value) and value >= 0 -> trunc(value)
        _absent -> nil
      end
    end)
  end
end
