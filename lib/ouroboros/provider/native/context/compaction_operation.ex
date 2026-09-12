defmodule Ouroboros.Provider.Native.Context.CompactionOperation do
  @moduledoc false

  @filename "compaction-operations.term"
  @limit 32

  @doc false
  def path(session_dir), do: Path.join(session_dir, @filename)

  def load(session_dir) do
    case File.read(path(session_dir)) do
      {:ok, bytes} ->
        try do
          operations =
            bytes
            |> :erlang.binary_to_term([:safe])
            |> List.wrap()
            |> Enum.map(&recover_unsettled/1)
            |> Map.new(&{&1.id, &1})

          if Enum.any?(operations, fn {_id, operation} ->
               operation.status in [:interrupted, :ambiguous]
             end) do
            case rewrite(session_dir, operations) do
              {:ok, persisted} ->
                persisted

              {:error, reason} ->
                raise ArgumentError,
                      "could not persist compaction operation recovery: #{inspect(reason)}"
            end
          else
            operations
          end
        rescue
          error ->
            raise ArgumentError,
                  "invalid compaction operation store: #{Exception.message(error)}"
        end

      {:error, :enoent} ->
        %{}

      {:error, reason} ->
        raise ArgumentError, "unreadable compaction operation store: #{inspect(reason)}"
    end
  end

  def load_file(session_dir), do: load(session_dir)

  def put(session_dir, operations, operation) do
    if not Map.has_key?(operations, operation.id) and map_size(operations) >= @limit do
      {:error, :compaction_operation_capacity}
    else
      operations = Map.put(operations, operation.id, operation)
      rewrite(session_dir, operations)
    end
  end

  defp rewrite(session_dir, operations) do
    target = path(session_dir)

    temporary =
      target <> ".tmp-" <> Base.url_encode64(:crypto.strong_rand_bytes(6), padding: false)

    bytes = :erlang.term_to_binary(Map.values(operations), compressed: 6)

    with :ok <- File.write(temporary, bytes, [:binary, :sync]),
         :ok <- File.chmod(temporary, 0o600),
         :ok <- File.rename(temporary, target),
         :ok <- Ouroboros.Audit.File.sync_directory(session_dir) do
      {:ok, operations}
    else
      {:error, reason} ->
        File.rm(temporary)
        {:error, {:compaction_operation_write_failed, reason}}
    end
  end

  defp recover_unsettled(%{status: :running} = operation) do
    operation
    |> Map.drop([:pid, :monitor])
    |> Map.merge(%{
      status: :interrupted,
      error: "the runtime stopped while compaction was running; its outcome was not committed",
      finished_at: DateTime.utc_now()
    })
  end

  defp recover_unsettled(%{status: :committing} = operation) do
    operation
    |> Map.drop([:pid, :monitor])
    |> Map.merge(%{
      status: :ambiguous,
      error:
        "the conversation commit began before the runtime stopped; query context before any new compaction",
      finished_at: DateTime.utc_now()
    })
  end

  defp recover_unsettled(operation), do: Map.drop(operation, [:pid, :monitor])
end
