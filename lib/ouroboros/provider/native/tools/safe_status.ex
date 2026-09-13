defmodule Ouroboros.Provider.Native.Tools.SafeStatus do
  @moduledoc """
  Read-only presentation of the privacy-bounded status produced by this session's owner.

  The model supplies no identity or facts. The native loop provides a closure bound to its
  owning interactive coordinator; one-shot and detached sessions report unavailable.
  """

  use Ouroboros.Action,
    name: "safe_status",
    description:
      "Read this session's owner-generated privacy-bounded runtime status. Identity, activity, posture, deadlines and credential presence are suppressed when unavailable or stale; this tool accepts no caller-selected owner or facts.",
    schema: []

  @impl true
  def run(_params, %{safe_status: fetch}) when is_function(fetch, 0) do
    case fetch.() do
      {:ok, status} when is_map(status) ->
        {:ok, %{output: JSON.encode!(status), is_error: false}}

      {:error, reason} ->
        {:ok, %{output: "Safe status unavailable: #{inspect(reason)}", is_error: true}}

      _ ->
        unavailable()
    end
  rescue
    _ -> unavailable()
  catch
    :exit, _ -> unavailable()
  end

  def run(_params, _context), do: unavailable()

  defp unavailable,
    do: {:ok, %{output: "Safe status unavailable: no owning interactive session", is_error: true}}
end
