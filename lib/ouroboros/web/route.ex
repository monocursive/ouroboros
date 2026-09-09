defmodule Ouroboros.Web.Route do
  @moduledoc false

  @spec session(atom(), String.t()) :: String.t()
  def session(plane, id) when plane in [:interactive, :coding] and is_binary(id) do
    "/s/#{plane}/#{segment(id)}"
  end

  @spec segment(String.t()) :: String.t()
  def segment(value) when is_binary(value), do: URI.encode(value, &URI.char_unreserved?/1)
end
