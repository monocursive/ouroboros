defmodule Ouroboros.Web.Transcript.Text do
  @moduledoc """
  The byte-bounded string arithmetic the projection accumulates with.

  Ports `bound_owned`, `bounded_copy`, `append_bounded` and `fitting_marker`
  (`tui/src/ui/transcript_cells.rs:4170-4237`). Every limit is in **bytes** and every cut
  lands on a UTF-8 character boundary, as it does there.
  """

  alias Ouroboros.Web.Presentation

  @doc "Cuts `text` to `limit` bytes on a character boundary, appending `marker`."
  @spec bounded_copy(String.t(), non_neg_integer(), String.t()) :: String.t()
  defdelegate bounded_copy(text, limit, marker), to: Presentation

  @doc """
  Appends only the prefix the transcript owns.

  Once the marker is present, later stream deltas are deliberately ignored by this
  projection; their source events remain complete. Returns the new text and whether the
  budget is now spent (`tui/src/ui/transcript_cells.rs:4197`).
  """
  @spec append_bounded(String.t(), String.t(), non_neg_integer(), String.t()) ::
          {String.t(), boolean()}
  def append_bounded(target, text, limit, marker) do
    cond do
      String.ends_with?(target, marker) ->
        {target, true}

      byte_size(target) + byte_size(text) <= limit ->
        {target <> text, false}

      true ->
        marker = fitting_marker(marker, limit)
        content_limit = max(limit - byte_size(marker), 0)

        kept =
          if byte_size(target) > content_limit do
            binary_part(target, 0, char_boundary_at_or_before(target, content_limit))
          else
            available = content_limit - byte_size(target)
            target <> binary_part(text, 0, char_boundary_at_or_before(text, available))
          end

        {kept <> marker, true}
    end
  end

  @doc "The marker that fits in `limit`, degrading to `…` and then to nothing."
  @spec fitting_marker(String.t(), non_neg_integer()) :: String.t()
  def fitting_marker(marker, limit) do
    cond do
      byte_size(marker) <= limit -> marker
      byte_size("…") <= limit -> "…"
      true -> ""
    end
  end

  @doc "The largest character boundary at or before `limit` bytes."
  @spec char_boundary_at_or_before(String.t(), non_neg_integer()) :: non_neg_integer()
  def char_boundary_at_or_before(text, limit) do
    walk_back(text, min(limit, byte_size(text)))
  end

  defp walk_back(_text, 0), do: 0

  defp walk_back(text, boundary) do
    <<byte>> = binary_part(text, boundary, 1)

    if Bitwise.band(byte, 0xC0) == 0x80 do
      walk_back(text, boundary - 1)
    else
      boundary
    end
  end

  @doc """
  A value rendered as the text a tool row quotes, bounded.

  Ports `bounded_compact` (`tui/src/ui/transcript_cells.rs:4239`): a string as itself, a
  wire marker as its short label, anything else as sorted JSON cut to `limit`.
  """
  @spec bounded_compact(term(), non_neg_integer(), String.t()) :: String.t()
  def bounded_compact(value, limit, marker) when is_binary(value),
    do: bounded_copy(value, limit, marker)

  def bounded_compact(fields, limit, marker)
      when is_map(fields) and not is_struct(fields) and map_size(fields) == 1 do
    cond do
      is_binary(inspected = Map.get(fields, "_opaque")) ->
        bounded_copy(inspected, limit, marker)

      Map.has_key?(fields, "_truncated") ->
        "<truncated>"

      is_binary(encoded = Map.get(fields, "_b64")) ->
        "<#{byte_size(encoded)} base64 bytes>"

      true ->
        bounded_copy(Presentation.encode_json(fields), limit, marker)
    end
  end

  def bounded_compact(value, limit, marker),
    do: bounded_copy(Presentation.encode_json(value), limit, marker)

  @doc "Rust's `str::lines`, so a line count means the same on both surfaces."
  @spec lines(String.t()) :: [String.t()]
  defdelegate lines(text), to: Presentation

  @doc "How many lines `text` holds, by the same rule."
  @spec line_count(String.t()) :: non_neg_integer()
  def line_count(text), do: length(lines(text))
end
