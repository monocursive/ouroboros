# Stop Ouroboros before encryption. Uses only an explicitly supplied policy and data root.
# mix run --no-start scripts/audit-maintenance.exs scan /absolute/data /absolute/audit-policy.json
# mix run --no-start scripts/audit-maintenance.exs encrypt /absolute/data /absolute/audit-policy.json
case System.argv() do
  [operation, root, policy] when operation in ["scan", "encrypt"] ->
    if Path.type(root) != :absolute, do: raise("an absolute data directory is required")
    config = Ouroboros.Audit.Config.from_environment!(root, %{"OUROBOROS_AUDIT_CONFIG" => policy})
    if operation == "encrypt" do
      case Ouroboros.Audit.Content.migrate(root, config) do
        {:ok, _} -> :ok
        error -> raise("migration failed: #{inspect(error)}")
      end
    end
    IO.puts(JSON.encode!(Ouroboros.Audit.Content.inventory(root, config)))
  _ -> raise("usage: audit-maintenance.exs scan|encrypt ABSOLUTE_DATA_DIR ABSOLUTE_POLICY_JSON")
end
