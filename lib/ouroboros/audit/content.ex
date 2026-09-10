defmodule Ouroboros.Audit.Content do
  @moduledoc "Encryption for managed operational state and artifacts, separate from audit capture policy."
  alias Ouroboros.Audit.Config
  @magic "OUROBOROS-ENCRYPTED-1\n"
  @aad "ouroboros.operational-content.v1"

  def encode(bytes, config \\ Config.current()) when is_binary(bytes) do
    if config.encryption_key_id do
      id = config.encryption_key_id
      nonce = :crypto.strong_rand_bytes(12)

      {ciphertext, tag} =
        :crypto.crypto_one_time_aead(
          :aes_256_gcm,
          Map.fetch!(config.encryption_keys, id),
          nonce,
          bytes,
          @aad <> id,
          true
        )

      @magic <>
        JSON.encode!(%{
          "key_id" => id,
          "nonce" => Base.encode64(nonce),
          "tag" => Base.encode64(tag),
          "ciphertext" => Base.encode64(ciphertext)
        })
    else
      bytes
    end
  end

  def decode(bytes, config \\ Config.current())

  def decode(@magic <> encoded, config) do
    with {:ok, envelope} <- JSON.decode(encoded),
         id when is_binary(id) <- envelope["key_id"],
         {:ok, key} <- Map.fetch(config.encryption_keys, id),
         {:ok, nonce} <- Base.decode64(envelope["nonce"]),
         true <- byte_size(nonce) == 12,
         {:ok, tag} <- Base.decode64(envelope["tag"]),
         true <- byte_size(tag) == 16,
         {:ok, ciphertext} <- Base.decode64(envelope["ciphertext"]),
         plaintext when is_binary(plaintext) <-
           :crypto.crypto_one_time_aead(
             :aes_256_gcm,
             key,
             nonce,
             ciphertext,
             @aad <> id,
             tag,
             false
           ) do
      {:ok, plaintext}
    else
      _ -> {:error, :operational_content_key_or_integrity_failure}
    end
  rescue
    _ -> {:error, :operational_content_key_or_integrity_failure}
  end

  # Legacy state remains readable for a forward migration. Every subsequent commit is
  # encrypted; the doctor identifies remaining plaintext files before firm deployment.
  def decode(bytes, _), do: {:ok, bytes}

  def read(path) do
    with {:ok, bytes} <- File.read(path), do: decode(bytes)
  end

  def encrypted?(bytes), do: String.starts_with?(bytes, @magic)

  @doc "Read-only inventory of managed operational content, excluding workspace files and credentials."
  def inventory(data_dir, config \\ Config.current())

  def inventory(nil, _),
    do: %{scope: "no_durable_data_directory", encrypted: 0, plaintext: [], unreadable: []}

  def inventory(data_dir, config) do
    files = managed_files(data_dir)

    Enum.reduce(
      files,
      %{
        scope: "managed_checkpoints_native_conversations_compaction_blobs_attachments_and_output",
        encrypted: 0,
        plaintext: [],
        unreadable: []
      },
      fn path, result ->
        relative = Path.relative_to(path, data_dir)

        case inspect_file(path, config) do
          :encrypted -> Map.update!(result, :encrypted, &(&1 + 1))
          :plaintext -> Map.update!(result, :plaintext, &[relative | &1])
          _ -> Map.update!(result, :unreadable, &[relative | &1])
        end
      end
    )
  end

  @doc "Offline forward encryption of managed content; never rewrites canonical audit records."
  def migrate(data_dir, config \\ Config.current()) do
    with true <- is_nil(Process.whereis(Ouroboros.Supervisor)),
         true <- config.encryption_key_id != nil do
      Enum.reduce_while(managed_files(data_dir), {:ok, 0}, fn path, {:ok, count} ->
        with :ok <- Ouroboros.Audit.File.no_symlinks(Path.dirname(path)),
             {:ok, bytes} <- Ouroboros.Audit.File.read(path),
             {:ok, clear} <- decode(bytes, config),
             :ok <- File.chmod(path, 0o600),
             :ok <- Ouroboros.Audit.File.atomic(path, encode(clear, config)) do
          {:cont, {:ok, count + 1}}
        else
          _ -> {:halt, {:error, {:migration_stopped, Path.relative_to(path, data_dir)}}}
        end
      end)
    else
      _ -> {:error, :migration_requires_stopped_runtime_and_key}
    end
  end

  defp managed_files(data_dir) do
    root = Path.expand(data_dir)

    patterns = [
      "*/checkpoints/*.term",
      "native/*/conversation.json",
      "native/*/manifest.json",
      "native/*/compaction/*.json",
      "native/*/blobs/*",
      "native/*/attachments/*",
      "native/*/output/*"
    ]

    files =
      Enum.flat_map(patterns, &Path.wildcard(Path.join(root, &1))) |> Enum.uniq() |> Enum.sort()

    if length(files) > 100_000, do: raise("operational privacy inventory exceeds 100000 files")
    files
  end

  defp inspect_file(path, config) do
    with :ok <- Ouroboros.Audit.File.no_symlinks(Path.dirname(path)),
         {:ok, %{type: :regular, size: size}} <- File.lstat(path),
         true <- size <= 89_479_488,
         {:ok, bytes} <- Ouroboros.Audit.File.read(path) do
      if encrypted?(bytes) do
        case decode(bytes, config) do
          {:ok, _} -> :encrypted
          _ -> :unreadable
        end
      else
        :plaintext
      end
    end
  end
end
