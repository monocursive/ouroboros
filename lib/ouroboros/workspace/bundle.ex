defmodule Ouroboros.Workspace.Bundle do
  @moduledoc false
  # The same bounded, digest-checked receiver is used for outbound and return bundles.
  # Owners serialize imports and decide where a verified bundle may be fetched.
  alias Ouroboros.Workspace.Git
  @chunk_bytes 1024 * 1024
  @max_bytes 256 * 1024 * 1024
  @deadline_ms 600_000

  def chunk_bytes, do: @chunk_bytes
  def max_bytes, do: @max_bytes

  def begin(directory, metadata) do
    with true <- valid_metadata?(metadata),
         :ok <- File.mkdir_p(directory),
         token = Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false),
         path = Path.join(directory, "incoming-#{token}.part"),
         :ok <- File.write(path, "", [:exclusive, :binary]),
         :ok <- File.chmod(path, 0o600) do
      {:ok,
       %{
         token: token,
         path: path,
         metadata: metadata,
         bytes: 0,
         digest: :crypto.hash_init(:sha256),
         deadline: now() + @deadline_ms
       }}
    else
      false -> {:error, :invalid_bundle_metadata}
      {:error, _} = error -> error
    end
  end

  def append(transfer, offset, data) do
    cond do
      now() > transfer.deadline ->
        {:error, :transfer_expired}

      not is_binary(data) or byte_size(data) > @chunk_bytes or byte_size(data) == 0 ->
        {:error, :invalid_chunk}

      offset != transfer.bytes ->
        {:error, :unexpected_chunk_offset}

      transfer.bytes + byte_size(data) > transfer.metadata.bytes ->
        {:error, :bundle_size_exceeded}

      true ->
        case File.write(transfer.path, data, [:append, :binary]) do
          :ok ->
            {:ok,
             %{
               transfer
               | bytes: transfer.bytes + byte_size(data),
                 digest: :crypto.hash_update(transfer.digest, data)
             }}

          error ->
            error
        end
    end
  end

  def verify(transfer) do
    cond do
      now() > transfer.deadline ->
        {:error, :transfer_expired}

      transfer.bytes != transfer.metadata.bytes ->
        {:error, :bundle_size_mismatch}

      Base.encode16(:crypto.hash_final(transfer.digest), case: :lower) != transfer.metadata.sha256 ->
        {:error, :bundle_digest_mismatch}

      true ->
        :ok
    end
  end

  def discard(transfer), do: File.rm(transfer.path)
  def expired?(transfer), do: now() > transfer.deadline

  def reconcile(directory) do
    Path.wildcard(Path.join(directory, "incoming-*.part")) |> Enum.each(&File.rm/1)
  end

  def metadata(path, commit, task_id, max_bytes \\ @max_bytes) do
    with {:ok, %{type: :regular, size: size}} <- File.lstat(path),
         true <- size > 0 and size <= min(max_bytes, @max_bytes) do
      digest =
        File.stream!(path, @chunk_bytes)
        |> Enum.reduce(:crypto.hash_init(:sha256), &:crypto.hash_update(&2, &1))
        |> :crypto.hash_final()
        |> Base.encode16(case: :lower)

      {:ok, %{commit: commit, task_id: task_id, bytes: size, sha256: digest}}
    else
      false -> {:error, {:bundle_too_large, max_bytes}}
      {:error, _} = error -> error
    end
  end

  defp valid_metadata?(%{commit: commit, task_id: task_id, bytes: bytes, sha256: sha}) do
    Git.valid_commit?(commit) and Git.valid_id?(task_id) and is_integer(bytes) and bytes > 0 and
      bytes <= @max_bytes and
      is_binary(sha) and Regex.match?(~r/\A[a-f0-9]{64}\z/, sha)
  end

  defp valid_metadata?(_), do: false
  defp now, do: System.monotonic_time(:millisecond)
end
