defmodule Ouroboros.Provider.Native.FileApproval do
  @moduledoc """
  Proposed file-tool input for an approval, not a computed filesystem diff.

  Only known file-tool fields are copied. No file is read to construct a preview and
  no input is changed for execution. Redact before excerpting so a cut cannot expose
  a prefix of a known secret. Each text leaf is bounded and explicitly marked when
  incomplete; the ordinary event redaction still runs afterwards.
  """

  @limit 32 * 1024

  def attach(payload, %{name: name, input: input}) when is_map(input) do
    fields =
      case name do
        "apply_patch" -> ~w(patch)
        "write" -> ~w(path content)
        "edit" -> ~w(path old_string new_string replace_all)
        _ -> []
      end

    if fields == [] do
      payload
    else
      preview =
        input
        |> Map.take(fields)
        |> Ouroboros.Redaction.redact()
        |> Map.new(fn {key, value} -> {key, bounded(value)} end)

      Map.put(payload, "proposed_change", preview)
    end
  end

  def attach(payload, _call), do: payload

  defp bounded(text) when is_binary(text) and byte_size(text) > @limit do
    %{
      "_excerpt" => Ouroboros.EventPresentation.bounded_copy(text, @limit, ""),
      "_bytes" => byte_size(text)
    }
  end

  defp bounded(value), do: value
end
