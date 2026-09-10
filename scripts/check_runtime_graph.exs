# Run with MIX_ENV=prod mix run --no-start scripts/check_runtime_graph.exs.
# Inspect .app metadata without starting services or reading runtime checkpoints.
retired = [:jido, :jido_action, :jido_signal, :jido_ai, :jido_harness]

visit = fn visit, app, seen ->
  if MapSet.member?(seen, app) do
    seen
  else
    case Application.load(app) do
      :ok -> :ok
      {:error, {:already_loaded, ^app}} -> :ok
      failure -> raise "cannot inspect #{app}: #{inspect(failure)}"
    end

    optional = Application.spec(app, :optional_applications)

    dependencies =
      (Application.spec(app, :applications) ++ Application.spec(app, :included_applications))
      |> Enum.reject(fn dependency ->
        dependency in optional and :code.where_is_file(~c"#{dependency}.app") == :non_existing
      end)

    Enum.reduce(dependencies, MapSet.put(seen, app), &visit.(visit, &1, &2))
  end
end

graph = visit.(visit, :ouroboros, MapSet.new())
remaining = Enum.filter(retired, &MapSet.member?(graph, &1))
if remaining != [], do: raise("retired runtime dependencies: #{inspect(remaining)}")

beams =
  Enum.filter(:code.all_available(), fn {module, _path, _loaded} ->
    name = to_string(module)
    name == "Elixir.Jido" or String.starts_with?(name, "Elixir.Jido.")
  end)

if beams != [], do: raise("retired executable modules on code path: #{inspect(beams)}")

IO.puts("Runtime graph: " <> Enum.map_join(Enum.sort(graph), ", ", &Atom.to_string/1))
IO.puts("No retired runtime applications or executable modules are available.")
