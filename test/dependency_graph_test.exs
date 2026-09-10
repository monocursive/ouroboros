defmodule Ouroboros.DependencyGraphTest do
  use ExUnit.Case, async: true

  test "the runtime graph and code path contain no removed framework" do
    retired = [:jido, :jido_action, :jido_signal, :jido_ai, :jido_harness]
    graph = visit(:ouroboros, MapSet.new())
    assert Enum.filter(retired, &MapSet.member?(graph, &1)) == []

    assert Enum.filter(:code.all_available(), fn {module, _path, _loaded} ->
             name = to_string(module)
             name == "Elixir.Jido" or String.starts_with?(name, "Elixir.Jido.")
           end) == []
  end

  defp visit(app, seen) do
    if MapSet.member?(seen, app) do
      seen
    else
      case Application.load(app) do
        :ok -> :ok
        {:error, {:already_loaded, ^app}} -> :ok
      end

      optional = Application.spec(app, :optional_applications)

      dependencies =
        (Application.spec(app, :applications) ++ Application.spec(app, :included_applications))
        |> Enum.reject(fn dependency ->
          dependency in optional and :code.where_is_file(~c"#{dependency}.app") == :non_existing
        end)

      Enum.reduce(dependencies, MapSet.put(seen, app), &visit/2)
    end
  end
end
