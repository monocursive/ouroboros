defmodule Ouroboros.Orchestration.Serializable do
  @moduledoc false

  @spec valid?(term()) :: boolean()
  def valid?(term) when is_pid(term) or is_port(term) or is_reference(term) or is_function(term),
    do: false

  def valid?([]), do: true
  def valid?([head | tail]), do: valid?(head) and valid?(tail)

  def valid?(term) when is_tuple(term) do
    term
    |> Tuple.to_list()
    |> Enum.all?(&valid?/1)
  end

  def valid?(term) when is_map(term) do
    term
    |> Map.to_list()
    |> Enum.all?(fn {key, value} -> valid?(key) and valid?(value) end)
  end

  def valid?(_term), do: true

  @spec safe(term()) :: term()
  def safe(term) do
    if valid?(term), do: term, else: {:unserializable, inspect(term, limit: 20)}
  end
end
