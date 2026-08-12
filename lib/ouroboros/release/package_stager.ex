defmodule Ouroboros.Release.PackageStager do
  @moduledoc """
  Publishes approved release bytes under an immutable content-addressed name.

  The adapter-selected releases directory is an operating-system trust boundary:
  Ouroboros requires it to exist and assumes only the deployment identity can
  mutate it. Bytes are synced before an exclusive hard-link publishes the final
  name, and the directory is synced before success is returned.
  """

  @basename_prefix "ouroboros-release-sha256-"

  @spec stage(module(), String.t(), binary()) ::
          {:ok, %{basename: String.t(), path: Path.t()}} | {:error, term()}
  def stage(adapter, sha256, binary)
      when is_atom(adapter) and is_binary(sha256) and is_binary(binary) do
    with :ok <- validate_digest(sha256, binary),
         basename = @basename_prefix <> sha256,
         {:ok, path} <- adapter_path(adapter, basename),
         :ok <- validate_adapter_path(path, basename),
         :ok <- ensure_existing_directory(Path.dirname(path)),
         :ok <- publish_once(path, binary, sha256) do
      {:ok, %{basename: basename, path: path}}
    end
  end

  def stage(_adapter, _sha256, _binary), do: {:error, :invalid_staged_release}

  defp validate_digest(sha256, binary) do
    actual = digest(binary)

    if byte_size(sha256) == 64 and sha256 =~ ~r/\A[0-9a-f]{64}\z/ and actual == sha256,
      do: :ok,
      else: {:error, {:staged_release_digest_mismatch, sha256, actual}}
  end

  defp adapter_path(adapter, basename) do
    result =
      try do
        adapter.package_path(String.to_charlist(basename))
      rescue
        error -> {:error, {:adapter_exception, error}}
      catch
        kind, reason -> {:error, {:adapter_exit, kind, reason}}
      end

    case result do
      {:error, reason} ->
        {:error, {:release_package_path_unavailable, reason}}

      path when is_binary(path) ->
        {:ok, Path.expand(path)}

      path when is_list(path) ->
        try do
          {:ok, path |> List.to_string() |> Path.expand()}
        rescue
          _error -> {:error, :invalid_release_package_path}
        end

      _other ->
        {:error, :invalid_release_package_path}
    end
  end

  defp validate_adapter_path(path, basename) do
    expected = basename <> ".tar.gz"

    if Path.basename(path) == expected,
      do: :ok,
      else: {:error, {:invalid_staged_release_path, path, expected}}
  end

  defp ensure_existing_directory(directory) do
    case File.lstat(directory) do
      {:ok, %{type: :directory}} -> :ok
      {:ok, %{type: type}} -> {:error, {:invalid_releases_directory, directory, type}}
      {:error, reason} -> {:error, {:releases_directory_unavailable, directory, reason}}
    end
  end

  defp publish_once(path, binary, sha256) do
    temporary = temporary_path(path)

    with {:ok, device} <- open_exclusive(temporary),
         :ok <- write_sync_close(device, binary) do
      publish_link(temporary, path, sha256)
    else
      {:error, reason} ->
        _ = File.rm(temporary)
        {:error, {:staged_release_write_failed, reason}}
    end
  end

  defp open_exclusive(path) do
    :file.open(String.to_charlist(path), [:write, :binary, :raw, :exclusive])
  end

  defp write_sync_close(device, binary) do
    write_result =
      with :ok <- :file.write(device, binary),
           :ok <- :file.sync(device) do
        :ok
      end

    close_result = :file.close(device)

    case {write_result, close_result} do
      {:ok, :ok} -> :ok
      {{:error, reason}, _close} -> {:error, reason}
      {:ok, {:error, reason}} -> {:error, reason}
    end
  end

  defp publish_link(temporary, path, sha256) do
    result =
      case File.ln(temporary, path) do
        :ok -> sync_directory(Path.dirname(path))
        {:error, :eexist} -> verify_existing(path, sha256)
        {:error, reason} -> {:error, reason}
      end

    remove_result = File.rm(temporary)

    with :ok <- result,
         :ok <- normalize_remove(remove_result) do
      :ok
    else
      {:error, _reason} = error -> error
    end
  end

  defp verify_existing(path, sha256) do
    with {:ok, %{type: :regular}} <- File.lstat(path),
         {:ok, binary} <- File.read(path),
         true <- digest(binary) == sha256 || {:error, {:staged_release_collision, path}} do
      :ok
    else
      {:ok, %{type: type}} -> {:error, {:invalid_staged_release_file, path, type}}
      {:error, _reason} = error -> error
    end
  end

  defp sync_directory(directory) do
    case :file.open(String.to_charlist(directory), [:read, :raw, :directory]) do
      {:ok, device} ->
        sync_result = :file.sync(device)
        close_result = :file.close(device)

        case {sync_result, close_result} do
          {:ok, :ok} -> :ok
          {{:error, reason}, _close} -> {:error, {:directory_sync_failed, directory, reason}}
          {:ok, {:error, reason}} -> {:error, {:directory_close_failed, directory, reason}}
        end

      {:error, reason} ->
        {:error, {:directory_open_failed, directory, reason}}
    end
  end

  defp normalize_remove(:ok), do: :ok
  defp normalize_remove({:error, :enoent}), do: :ok
  defp normalize_remove({:error, reason}), do: {:error, reason}

  defp temporary_path(path) do
    suffix = :crypto.strong_rand_bytes(12) |> Base.url_encode64(padding: false)
    path <> ".tmp-" <> suffix
  end

  defp digest(binary), do: :crypto.hash(:sha256, binary) |> Base.encode16(case: :lower)
end
