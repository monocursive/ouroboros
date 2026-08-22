defmodule Ouroboros.CodeIntel.Diagnostics do
  @moduledoc """
  Normalises, dedupes, and bounds one `textDocument/publishDiagnostics` payload.

  Three things happen here and each has a documented failure behind it. Items become
  plain maps with 0-based positions, because everything downstream — a gateway method, a
  TUI badge, a diff against a pre-edit baseline — needs a shape it can compare and
  serialise. Duplicates are collapsed on `(code, severity, message, range)`, the key
  OpenCode settled on, because servers re-report the same finding from several passes.
  And the list is capped: thousands of diagnostics in one file stalled Claude Code's UI
  for multiple seconds (v2.1.216), so past the cap the extras are counted, not kept.

  Severity is an atom here and an integer on the wire. A payload with no severity is
  `nil` rather than a guess, and a caller filtering for errors will not see it — which is
  the right way round, because inventing a severity is how a warning becomes a blocker.
  """

  @type item :: %{
          range: map(),
          severity: :error | :warning | :information | :hint | nil,
          code: String.t() | integer() | nil,
          source: String.t() | nil,
          message: String.t(),
          tags: [integer()]
        }

  @doc """
  Returns the normalised, deduped, capped items and how many were dropped by the cap.
  """
  @spec normalize(term(), pos_integer()) :: {[item()], non_neg_integer()}
  def normalize(items, cap) when is_list(items) and is_integer(cap) and cap > 0 do
    deduped =
      items
      |> Enum.flat_map(&item/1)
      |> Enum.uniq_by(&{&1.code, &1.severity, &1.message, &1.range})

    kept = Enum.take(deduped, cap)
    {kept, length(deduped) - length(kept)}
  end

  def normalize(_items, _cap), do: {[], 0}

  @doc "Counts by severity, with an `:unknown` bucket rather than a silent drop."
  @spec counts([item()]) :: %{atom() => non_neg_integer()}
  def counts(items) do
    Enum.reduce(items, %{error: 0, warning: 0, information: 0, hint: 0, unknown: 0}, fn item,
                                                                                        acc ->
      key = item.severity || :unknown
      Map.update(acc, key, 1, &(&1 + 1))
    end)
  end

  defp item(%{"range" => range} = raw) when is_map(range) do
    [
      %{
        range: normalize_range(range),
        severity: severity(raw["severity"]),
        code: code(raw["code"]),
        source: string_or_nil(raw["source"]),
        message: to_string(raw["message"] || ""),
        tags: raw["tags"] |> List.wrap() |> Enum.filter(&is_integer/1)
      }
    ]
  end

  # A diagnostic with no range cannot be placed, diffed, or shown against a line. It is
  # dropped rather than given position zero, which would put a stranger's error on the
  # first line of the user's file.
  defp item(_raw), do: []

  defp normalize_range(%{"start" => start_position, "end" => end_position}) do
    %{start: position(start_position), end: position(end_position)}
  end

  defp normalize_range(_range), do: %{start: position(nil), end: position(nil)}

  defp position(%{"line" => line, "character" => character})
       when is_integer(line) and is_integer(character),
       do: %{line: max(line, 0), character: max(character, 0)}

  defp position(_other), do: %{line: 0, character: 0}

  @doc false
  @spec severity(term()) :: :error | :warning | :information | :hint | nil
  def severity(1), do: :error
  def severity(2), do: :warning
  def severity(3), do: :information
  def severity(4), do: :hint
  def severity(_other), do: nil

  defp code(value) when is_binary(value) or is_integer(value), do: value
  defp code(_other), do: nil

  defp string_or_nil(value) when is_binary(value), do: value
  defp string_or_nil(_other), do: nil
end
