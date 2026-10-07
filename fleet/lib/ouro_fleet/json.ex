defmodule OuroFleet.JSON do
  @moduledoc "JSON null is Elixir nil at every wire and checkpoint boundary."
  def decode(bytes), do: bytes |> :json.decode() |> convert(:decode)
  def encode(value), do: value |> convert(:encode) |> :json.encode()
  defp convert(nil, :encode), do: :null
  defp convert(:null, :decode), do: nil

  defp convert(value, mode) when is_map(value),
    do: Map.new(value, fn {key, item} -> {key, convert(item, mode)} end)

  defp convert(value, mode) when is_list(value), do: Enum.map(value, &convert(&1, mode))
  defp convert(value, _), do: value
end
