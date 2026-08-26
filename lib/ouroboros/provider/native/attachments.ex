defmodule Ouroboros.Provider.Native.Attachments do
  @moduledoc false

  @max_images 32
  @max_image_bytes 20 * 1024 * 1024
  @max_total_bytes 64 * 1024 * 1024

  @spec message(String.t(), [String.t()], String.t()) :: {:ok, map()} | {:error, term()}
  def message(text, [], session_dir) when is_binary(text) and is_binary(session_dir),
    do: {:ok, %{role: :user, content: text}}

  def message(text, attachments, session_dir)
      when is_binary(text) and is_list(attachments) and is_binary(session_dir) do
    with :ok <- validate_count(attachments),
         {:ok, images, files} <- stage_all(attachments, session_dir) do
      content =
        [%{type: :text, text: text}] ++
          images ++ file_mentions(files)

      {:ok, %{role: :user, content: content}}
    end
  end

  defp validate_count(attachments) when length(attachments) <= @max_images, do: :ok
  defp validate_count(_attachments), do: {:error, {:too_many_attachments, @max_images}}

  defp stage_all(paths, session_dir) do
    Enum.reduce_while(paths, {:ok, [], [], 0}, fn path, {:ok, images, files, total} ->
      case stage(path, session_dir) do
        {:ok, :file, staged} ->
          {:cont, {:ok, images, files ++ [staged], total}}

        {:ok, :image, %{size: size} = staged} when total + size <= @max_total_bytes ->
          {:cont, {:ok, images ++ [staged], files, total + size}}

        {:ok, :image, _staged} ->
          {:halt, {:error, {:attachments_too_large, @max_total_bytes}}}

        {:error, _reason} = error ->
          {:halt, error}
      end
    end)
    |> case do
      {:ok, images, files, _total} -> {:ok, images, files}
      {:error, _reason} = error -> error
    end
  end

  defp stage(path, session_dir) when is_binary(path) do
    case File.stat(path) do
      {:ok, %File.Stat{type: :regular}} ->
        case File.open(path, [:read, :binary], fn file ->
               {:attachment, stage_open(file, path, session_dir)}
             end) do
          {:ok, {:attachment, result}} -> result
          {:error, reason} -> {:error, {:invalid_attachment, path, reason}}
        end

      {:ok, %File.Stat{}} ->
        {:error, {:invalid_attachment, path, :not_regular}}

      {:error, reason} ->
        {:error, {:invalid_attachment, path, reason}}
    end
  end

  defp stage_open(file, path, session_dir) do
    case IO.binread(file, 12) do
      :eof ->
        {:ok, :file, path}

      {:error, reason} ->
        {:error, {:invalid_attachment, path, reason}}

      header when is_binary(header) ->
        case media_type(header) do
          nil -> {:ok, :file, path}
          _image -> stage_image(file, path, session_dir)
        end
    end
  end

  defp stage_image(file, path, session_dir) do
    with {:ok, 0} <- :file.position(file, :bof),
         bytes when is_binary(bytes) <- IO.binread(file, @max_image_bytes + 1) do
      case media_type(bytes) do
        nil ->
          {:error, {:invalid_attachment, path, :changed_while_reading}}

        _media_type when byte_size(bytes) > @max_image_bytes ->
          {:error, {:attachment_too_large, path, @max_image_bytes}}

        media_type ->
          persist_image(bytes, media_type, session_dir)
      end
    else
      :eof -> {:error, {:invalid_attachment, path, :changed_while_reading}}
      {:error, reason} -> {:error, {:invalid_attachment, path, reason}}
    end
  end

  defp persist_image(bytes, media_type, session_dir) do
    digest = :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)
    extension = extension(media_type)
    directory = Path.join(session_dir, "attachments")
    staged_path = Path.join(directory, digest <> extension)

    with :ok <- mkdir_private(directory),
         :ok <- write_once(staged_path, bytes) do
      {:ok, :image,
       %{
         type: :image,
         path: staged_path,
         media_type: media_type,
         sha256: digest,
         size: byte_size(bytes)
       }}
    end
  end

  defp file_mentions([]), do: []

  defp file_mentions(paths) do
    text = Enum.map_join(paths, "\n", &("@" <> &1))
    [%{type: :text, text: "Files available through the read tool:\n" <> text}]
  end

  @doc """
  The image media type for a byte prefix, or `nil` when the magic bytes are not an image.

  Public because `Ouroboros.Provider.Native.Desktop` stages helper screenshots against the
  same one magic-byte table rather than keeping a second, driftable copy of it.
  """
  @spec media_type(binary()) :: String.t() | nil
  def media_type(<<137, 80, 78, 71, 13, 10, 26, 10, _rest::binary>>), do: "image/png"
  def media_type(<<255, 216, 255, _rest::binary>>), do: "image/jpeg"
  def media_type(<<"GIF87a", _rest::binary>>), do: "image/gif"
  def media_type(<<"GIF89a", _rest::binary>>), do: "image/gif"
  def media_type(<<"RIFF", _size::binary-size(4), "WEBP", _rest::binary>>), do: "image/webp"
  def media_type(_bytes), do: nil

  defp extension("image/png"), do: ".png"
  defp extension("image/jpeg"), do: ".jpg"
  defp extension("image/gif"), do: ".gif"
  defp extension("image/webp"), do: ".webp"

  defp mkdir_private(path) do
    with :ok <- File.mkdir_p(path),
         :ok <- File.chmod(path, 0o700) do
      :ok
    end
  end

  defp write_once(path, bytes) do
    case File.write(path, bytes, [:binary, :exclusive]) do
      :ok -> File.chmod(path, 0o600)
      {:error, :eexist} -> verify_existing(path, bytes)
      {:error, reason} -> {:error, reason}
    end
  end

  defp verify_existing(path, bytes) do
    case File.read(path) do
      {:ok, ^bytes} -> :ok
      {:ok, _other} -> {:error, {:attachment_digest_collision, path}}
      {:error, reason} -> {:error, reason}
    end
  end
end
