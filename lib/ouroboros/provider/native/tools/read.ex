defmodule Ouroboros.Provider.Native.Tools.Read do
  @moduledoc """
  Read a slice of a file, line-numbered and bounded.

  Line numbers are in the output because every exact-string edit that follows depends
  on the model having seen the file, and a numbered read is how it reports *where* it
  is looking without inventing an anchor. The bound is 64 KiB per call: an unbounded
  read is the fastest way to spend a context window on one generated file
  (R3 §2, §8d).

  Every successful read records a fingerprint — mtime, size, and a content hash — which
  is what `Ouroboros.Provider.Native.Tools.Edit` checks before it rewrites the file.
  """

  use Jido.Action,
    name: "read",
    description:
      "Read a file from the workspace. Returns line-numbered text starting at `offset`. " <>
        "Read a file before editing it.",
    schema: [
      path: [
        type: :string,
        required: true,
        doc: "Absolute path, or a path relative to the workspace root."
      ],
      offset: [type: :non_neg_integer, default: 0, doc: "First line to return, 0-based."],
      limit: [type: :pos_integer, default: 2_000, doc: "How many lines to return."]
    ]

  alias Ouroboros.Provider.Native.Paths

  @max_bytes 64 * 1024

  @impl true
  def run(params, context) do
    with {:ok, path} <- Paths.resolve(params.path, context.scope),
         {:ok, stat} <- stat(path),
         {:ok, content} <- read(path) do
      {slice, note} = slice(content, params.offset, params.limit)

      {:ok,
       %{
         output: render(slice, params.offset) <> note,
         is_error: false,
         reads: %{path => fingerprint(stat, content)}
       }}
    else
      {:error, reason} -> {:ok, %{output: "read failed: #{describe(reason)}", is_error: true}}
    end
  end

  @doc false
  @spec fingerprint(File.Stat.t(), binary()) :: map()
  def fingerprint(stat, content) do
    %{
      mtime: stat.mtime,
      size: stat.size,
      hash: :sha256 |> :crypto.hash(content) |> Base.encode16(case: :lower)
    }
  end

  @doc false
  @spec fingerprint(String.t()) :: {:ok, map()} | {:error, term()}
  def fingerprint(path) do
    with {:ok, stat} <- stat(path),
         {:ok, content} <- read(path) do
      {:ok, fingerprint(stat, content)}
    end
  end

  defp stat(path) do
    case File.stat(path, time: :posix) do
      {:ok, %File.Stat{type: :regular} = stat} -> {:ok, stat}
      {:ok, %File.Stat{type: type}} -> {:error, {:not_a_regular_file, path, type}}
      {:error, reason} -> {:error, {:unreadable, path, reason}}
    end
  end

  defp read(path) do
    case File.read(path) do
      {:ok, content} -> {:ok, content}
      {:error, reason} -> {:error, {:unreadable, path, reason}}
    end
  end

  # A file whose bytes are not text is described, not dumped: a binary blob in the
  # transcript is unreadable for the operator and unusable for the model.
  defp slice(content, _offset, _limit) when not is_binary(content), do: {[], ""}

  defp slice(content, offset, limit) do
    if String.valid?(content) do
      lines = String.split(content, "\n")
      taken = lines |> Enum.drop(offset) |> Enum.take(limit)
      {taken, note(lines, taken, offset, limit)}
    else
      {[], "\n(binary file, #{byte_size(content)} bytes — not shown)"}
    end
  end

  defp note(lines, taken, offset, limit) do
    remaining = length(lines) - offset - length(taken)

    cond do
      offset >= length(lines) and lines != [""] ->
        "\n(offset #{offset} is past the end; the file has #{length(lines)} lines)"

      remaining > 0 ->
        "\n(#{remaining} more lines — read again with offset #{offset + limit})"

      true ->
        ""
    end
  end

  defp render([], _offset), do: ""

  defp render(lines, offset) do
    {rendered, truncated?} =
      lines
      |> Enum.with_index(offset + 1)
      |> Enum.reduce_while({[], false}, fn {line, number}, {acc, _truncated} ->
        entry = String.pad_leading(Integer.to_string(number), 6) <> "\t" <> line

        if IO.iodata_length(acc) + byte_size(entry) > @max_bytes,
          do: {:halt, {acc, true}},
          else: {:cont, {[acc, entry, "\n"], false}}
      end)

    text = IO.iodata_to_binary(rendered)
    if truncated?, do: text <> "(truncated at #{@max_bytes} bytes)\n", else: text
  end

  defp describe({:not_a_regular_file, path, type}), do: "#{path} is a #{type}, not a file"
  defp describe({:unreadable, path, reason}), do: "#{path}: #{:file.format_error(reason)}"
  defp describe(reason), do: Paths.describe_error(reason)
end
