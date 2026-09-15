defmodule Ouroboros.Attachments.Normalizer do
  @moduledoc false
  alias Ouroboros.Provider.Native.{Exec, Sandbox}

  @max_bytes 20 * 1024 * 1024

  def available? do
    File.regular?(helper()) and Sandbox.fences_network?(Sandbox.detect()) and
      Sandbox.fences_reads?(Sandbox.detect())
  end

  def helper do
    Application.get_env(:ouroboros, :image_helper_path) ||
      Path.join(:code.priv_dir(:ouroboros) |> to_string(), "media/ouro-media")
  end

  def normalize(chunks, directory) do
    work =
      Path.join(
        directory,
        "decode-" <> Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)
      )

    try do
      with true <- available?() || {:error, :image_decoder_unavailable},
           :ok <- File.mkdir(work),
           :ok <- File.chmod(work, 0o700),
           {:ok, work} <- Ouroboros.Workspace.Path.canonicalize(work),
           :ok <- source(chunks, Path.join(work, "source")),
           scratch = Path.join(work, "scratch"),
           :ok <- File.mkdir(scratch),
           executable = Path.expand(helper()),
           policy =
             Sandbox.helper_policy(readable: [executable], writable: [work], scratch: scratch),
           {:ok, {program, args}} <-
             Sandbox.wrap({:argv, [executable, work]}, %{root: work}, policy),
           {:ok, result} <-
             Exec.run(program, args,
               cd: work,
               timeout_ms: 5_000,
               max_bytes: 4096,
               env: Sandbox.env(policy)
             ),
           :ok <- result(result),
           {:ok, content} <- bounded_read(Path.join(work, "content.png"), @max_bytes),
           {:ok, thumbnail} <- bounded_read(Path.join(work, "thumbnail.png"), 256 * 1024),
           {:ok, metadata_bytes} <- bounded_read(Path.join(work, "metadata.json"), 4096),
           {:ok, %{"width" => width, "height" => height, "media_type" => "image/png"}} <-
             JSON.decode(metadata_bytes),
           true <-
             is_integer(width) and is_integer(height) and width > 0 and height > 0 and
               width <= 16_384 and height <= 16_384 and width * height <= 40_000_000 do
        {:ok, %{content: content, thumbnail: thumbnail, width: width, height: height}}
      else
        {:error, reason} -> {:error, reason}
        _ -> {:error, :attachment_invalid}
      end
    after
      File.rm_rf(work)
    end
  end

  defp source(chunks, path) do
    case File.open(path, [:write, :binary, :exclusive]) do
      {:ok, file} ->
        try do
          with :ok <- File.chmod(path, 0o600),
               :ok <-
                 Enum.reduce_while(chunks, :ok, fn chunk, :ok ->
                   with {:ok, bytes} <- Ouroboros.Audit.Content.read(chunk),
                        :ok <- IO.binwrite(file, bytes) do
                     {:cont, :ok}
                   else
                     error -> {:halt, error}
                   end
                 end) do
            :file.sync(file)
          end
        after
          File.close(file)
        end

      error ->
        error
    end
  end

  defp result(%{status: 0, truncated?: false, timed_out?: false}), do: :ok
  defp result(%{timed_out?: true}), do: {:error, :attachment_prepare_timeout}

  defp result(%{output: output}) do
    reason =
      Enum.find(
        [
          :attachment_animation_unsupported,
          :attachment_dimensions_exceeded,
          :attachment_too_large,
          :attachment_format_unsupported,
          :attachment_color_profile_invalid,
          :attachment_color_profile_unsupported
        ],
        :attachment_invalid,
        &String.contains?(output, Atom.to_string(&1))
      )

    {:error, reason}
  end

  defp bounded_read(path, max) do
    with {:ok, %{type: :regular, size: size}} when size <= max <- File.lstat(path),
         {:ok, bytes} <- File.read(path),
         true <- byte_size(bytes) <= max do
      {:ok, bytes}
    else
      _ -> {:error, :attachment_invalid}
    end
  end
end
