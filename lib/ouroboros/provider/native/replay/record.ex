defmodule Ouroboros.Provider.Native.Replay.Record do
  @moduledoc """
  Journal records, read back into the shapes the loop works in.

  The journal writes what `Ouroboros.Provider.Native.Journal.jsonable/1` could encode: a
  tuple became a list, an atom became its name, and any field over 256 KiB became a blob
  pointer. This module is the inverse where an inverse exists, and is explicit about where
  one does not — a blob the store has evicted comes back as `{:error, …}` and becomes a
  named replay boundary rather than an empty chunk list nobody notices.

  Nothing here guesses. `["finish", "stop"]` becomes `{:finish, :stop}` only because
  `:stop` already exists in this VM; an unknown finish reason stays a string, which the
  loop ignores exactly as it ignores an unknown chunk.
  """

  alias Ouroboros.Provider.Native.Journal

  @doc "The value of one record field, following a blob pointer if the field was spilled."
  @spec field(map(), String.t(), String.t() | nil) :: {:ok, term()} | {:error, term()}
  def field(record, key, session_dir) do
    case Map.get(record, key) do
      %{"blob" => _digest} = marker when is_binary(session_dir) ->
        Journal.resolve_blob(session_dir, marker)

      %{"blob" => _digest} = marker ->
        {:error, {:blob_unavailable, marker, :no_session_dir}}

      value ->
        {:ok, value}
    end
  end

  @doc """
  A `model_result` record's chunks, in the loop's own chunk vocabulary.

  The order is the order they streamed in, which is the order the loop replays them in and
  therefore the order the events come back out in.
  """
  @spec chunks(map(), String.t() | nil) :: {:ok, [tuple()]} | {:error, term()}
  def chunks(record, session_dir) do
    case field(record, "chunks", session_dir) do
      {:ok, chunks} when is_list(chunks) -> {:ok, Enum.map(chunks, &chunk/1)}
      {:ok, other} -> {:error, {:unreadable_chunks, other}}
      {:error, _reason} = error -> error
    end
  end

  defp chunk(["text", delta]) when is_binary(delta), do: {:text, delta}
  defp chunk(["thinking", delta]) when is_binary(delta), do: {:thinking, delta}

  defp chunk(["tool_call", %{} = call]),
    do:
      {:tool_call,
       %{
         id: Map.get(call, "id", ""),
         name: Map.get(call, "name", ""),
         input: Map.get(call, "input", %{})
       }}

  defp chunk(["reasoning_details", details]) when is_list(details),
    do: {:reasoning_details, details}

  defp chunk(["provider_metadata", %{} = metadata]), do: {:provider_metadata, metadata}
  defp chunk(["usage", %{} = usage]), do: {:usage, usage}
  defp chunk(["finish", reason]) when is_binary(reason), do: {:finish, existing_atom(reason)}
  defp chunk([kind, payload]) when is_binary(kind), do: {existing_atom(kind), payload}
  defp chunk(other), do: other

  defp existing_atom(name) do
    String.to_existing_atom(name)
  rescue
    ArgumentError -> name
  end

  @doc """
  The user message a `prompt` record describes, or why it cannot be rebuilt.

  Text is exact — the record holds the bytes that entered the conversation, after the
  `UserPromptSubmit` fold. Attachments are not: the record holds a pointer per attachment
  (`sha256`, `media_type`, `size`) and never the bytes, so a prompt that carried one cannot
  be reassembled into the message the model was sent. That is a bounded replay, and it says
  so here rather than replaying a different prompt.
  """
  @spec prompt(map(), String.t() | nil) :: {:ok, map()} | {:error, term()}
  def prompt(record, session_dir) do
    with {:ok, content} <- field(record, "content", session_dir),
         {:ok, attachments} <- field(record, "attachments", session_dir) do
      cond do
        attachments not in [nil, []] -> {:error, {:prompt_attachments, length(attachments)}}
        is_binary(content) -> {:ok, %{role: :user, content: content}}
        true -> {:error, {:unreadable_prompt, content}}
      end
    end
  end

  @doc "A `tool_result` record as the result map `Loop`'s recorded-tool source hands back."
  @spec tool_result(map(), String.t() | nil) :: {:ok, map()} | {:error, term()}
  def tool_result(record, session_dir) do
    with {:ok, content} <- field(record, "content", session_dir) do
      {:ok,
       %{
         call_id: Map.get(record, "call_id"),
         tool: Map.get(record, "tool"),
         output: content,
         is_error: Map.get(record, "is_error") == true,
         ledger_ref: Map.get(record, "ledger_ref"),
         seq: Map.get(record, "seq"),
         at: Map.get(record, "at")
       }}
    end
  end
end
