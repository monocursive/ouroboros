defmodule Ouroboros.Storage.DurableFile do
  @moduledoc """
  A Jido storage adapter whose checkpoint commits are durable before success.

  Checkpoints are serialized to an exclusive temporary file, synced, atomically
  renamed over the checkpoint, and followed by a parent-directory sync. A failure
  before rename is an ordinary error and leaves the old checkpoint standing. A failure
  after rename is `{:error, {:commit_outcome_unknown, reason}}`: the new inode is visible,
  but the directory entry was not proven durable. Callers must reconcile that outcome,
  never report it as a definite refusal while continuing with old in-memory state.

  Thread operations fail closed because this adapter is intentionally limited to
  Ouroboros mutation journals, which use checkpoint operations only.

  `:durability_hook` is a deterministic fault-observation seam for tests. A hook
  returning `{:error, reason}` aborts before the named operation.
  """

  @behaviour Jido.Storage

  @impl true
  def get_checkpoint(key, opts) do
    with {:ok, path} <- checkpoint_path(key, opts) do
      case File.read(path) do
        {:ok, binary} -> safe_binary_to_term(binary)
        {:error, :enoent} -> :not_found
        {:error, reason} -> {:error, reason}
      end
    end
  end

  @impl true
  def put_checkpoint(key, data, opts) do
    with {:ok, path} <- checkpoint_path(key, opts),
         :ok <- ensure_directory(Path.dirname(path)),
         temporary = temporary_path(path),
         :ok <- hook(opts, :before_open_temp),
         {:ok, device} <-
           :file.open(String.to_charlist(temporary), [:write, :binary, :raw, :exclusive]),
         :ok <- write_checkpoint(device, temporary, path, data, opts) do
      :ok
    else
      {:error, _reason} = error -> error
    end
  rescue
    error -> {:error, error}
  end

  @impl true
  def delete_checkpoint(key, opts) do
    with {:ok, path} <- checkpoint_path(key, opts),
         :ok <- hook(opts, :before_delete) do
      case remove_if_present(path) do
        {:ok, false} ->
          :ok

        {:ok, true} ->
          case sync_directory(Path.dirname(path), opts) do
            :ok -> :ok
            {:error, reason} -> {:error, {:commit_outcome_unknown, reason}}
          end

        {:error, _reason} = error ->
          error
      end
    end
  rescue
    error -> {:error, error}
  end

  @impl true
  def load_thread(_thread_id, _opts), do: {:error, :thread_operations_not_supported}

  @impl true
  def append_thread(_thread_id, _entries, _opts),
    do: {:error, :thread_operations_not_supported}

  @impl true
  def delete_thread(_thread_id, _opts), do: {:error, :thread_operations_not_supported}

  defp write_checkpoint(device, temporary, path, data, opts) do
    binary = :erlang.term_to_binary(data)

    precommit =
      with :ok <- hook(opts, :before_write),
           :ok <- :file.write(device, binary),
           :ok <- hook(opts, :before_file_sync),
           :ok <- :file.sync(device),
           :ok <- hook(opts, :before_close),
           :ok <- :file.close(device) do
        :ok
      end

    result =
      case precommit do
        :ok ->
          with :ok <- hook(opts, :before_rename),
               :ok <- File.rename(temporary, path) do
            directory_result =
              with :ok <- hook(opts, :before_directory_sync),
                   :ok <- sync_directory(Path.dirname(path), opts) do
                :ok
              end

            case directory_result do
              :ok -> :ok
              {:error, reason} -> {:error, {:commit_outcome_unknown, reason}}
            end
          end

        {:error, _reason} = error ->
          error
      end

    if precommit != :ok do
      _ = :file.close(device)
    end

    if result != :ok do
      _ = File.rm(temporary)
    end

    result
  end

  defp ensure_directory(directory) do
    case File.mkdir_p(directory) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp sync_directory(directory, opts) do
    with :ok <- hook(opts, :directory_sync),
         {:ok, device} <- :file.open(String.to_charlist(directory), [:read, :raw, :directory]) do
      result = :file.sync(device)
      close_result = :file.close(device)

      case {result, close_result} do
        {:ok, :ok} -> :ok
        {{:error, reason}, _close} -> {:error, {:directory_sync_failed, reason}}
        {:ok, {:error, reason}} -> {:error, {:directory_close_failed, reason}}
      end
    end
  end

  defp checkpoint_path(key, opts) do
    case Keyword.fetch(opts, :path) do
      {:ok, path} when is_binary(path) and path != "" ->
        hash =
          :crypto.hash(:sha256, :erlang.term_to_binary(key))
          |> Base.url_encode64(padding: false)

        {:ok, Path.join([Path.expand(path), "checkpoints", hash <> ".term"])}

      _other ->
        {:error, :invalid_storage_path}
    end
  end

  defp temporary_path(path) do
    suffix = :crypto.strong_rand_bytes(12) |> Base.url_encode64(padding: false)
    path <> ".tmp-" <> suffix
  end

  defp safe_binary_to_term(binary) do
    {:ok, :erlang.binary_to_term(binary, [:safe])}
  rescue
    ArgumentError -> {:error, :invalid_term}
  end

  defp remove_if_present(path) do
    case File.rm(path) do
      :ok -> {:ok, true}
      {:error, :enoent} -> {:ok, false}
      {:error, reason} -> {:error, reason}
    end
  end

  defp hook(opts, event) do
    case Keyword.get(opts, :durability_hook) do
      nil -> :ok
      hook when is_function(hook, 1) -> hook.(event)
      _invalid -> {:error, :invalid_durability_hook}
    end
  end
end
