defmodule Ouroboros.Provider.Native.Context.Handoff do
  @moduledoc """
  The packet a fresh session starts from when the operator hands off rather than compacts.

  Amp replaced compaction with Handoff because compacting a compacted conversation
  produces "summary on top of summary" (R3 §5, §8d). The difference is not the summary —
  both write one — it is what the summary is *for*: compaction keeps a session going past
  its window, handoff ends the session and starts a clean one that knows what the last
  one learned.

  So the packet is deliberately more than a summary. It carries:

    * the five-heading structure (Goal / Constraints / Progress / Decisions / Next steps),
      so the new session reads the same shape a compacted one would have;
    * **the files this session touched, with their current SHA-256** — the fact a summary
      cannot carry, and the one that stops the new session from re-reading a file it was
      told about and finding it different;
    * the open plan items, so a plan does not die with the session that made it;
    * the operator's own `prompt`, last, because it is the instruction and everything
      above it is context.

  Every hash is computed at handoff time from the file as it is *now*, not as it was when
  the tool wrote it. A file changed by something outside the session between then and now
  is reported at its current hash, which is the honest thing to hand to an agent that is
  about to read it.
  """

  @max_files 200
  @max_plan_items 40
  @max_plan_text_bytes 500
  @max_evidence_refs 16

  @typedoc "One file the parent session touched."
  @type file_entry :: %{path: String.t(), sha256: String.t() | nil, note: String.t() | nil}

  @doc """
  Builds the packet.

  Options:

    * `:summary` — the five-heading summary, or `nil` to render the section as absent
      rather than inventing one.
    * `:files` — the paths the session read or wrote, in any order.
    * `:plan` — the most recent `plan_updated` payload, or `nil`.
    * `:prompt` — the operator's instruction for the new session.
    * `:workspace` — the workspace root, for relative paths in the render.
    * `:parent` — the parent session's `provider_session_id`.
  """
  @spec packet(keyword()) :: String.t()
  def packet(opts) do
    paths = Keyword.get(opts, :files, [])
    files = hash_files(paths)
    counts = file_counts(paths)
    workspace = Keyword.get(opts, :workspace)

    """
    You are continuing work that another session started. That session is not gone — its
    transcript and its compaction archives are on this machine under session
    #{Keyword.get(opts, :parent) || "(unknown)"} — but you do not have its conversation.
    Everything you need is below. Verify before you rely on it: re-read a file rather
    than trusting a hash to mean you know its contents.

    ## Handed-off state

    #{summary_section(Keyword.get(opts, :summary))}

    ### Files the previous session touched

    #{files_section(files, workspace)}#{omission_section(counts.omitted)}

    ### Open plan

    #{plan_section(Keyword.get(opts, :plan))}

    ## Your instruction

    #{instruction_section(Keyword.get(opts, :prompt))}
    """
    |> String.trim()
  end

  @doc """
  Hashes each path as it stands now.

  A path that cannot be read is reported with `sha256: nil` and a note saying why, which
  is the only truthful thing to say about a file the handoff cannot see.
  """
  @spec hash_files([String.t()]) :: [file_entry()]
  def hash_files(paths) when is_list(paths) do
    paths
    |> Enum.filter(&is_binary/1)
    |> Enum.uniq()
    |> Enum.sort()
    |> Enum.take(@max_files)
    |> Enum.map(&hash_file/1)
  end

  def hash_files(_paths), do: []

  @doc "Counts eligible unique file paths before and after the packet cap."
  @spec file_counts([String.t()]) :: %{
          total: non_neg_integer(),
          retained: non_neg_integer(),
          omitted: non_neg_integer()
        }
  def file_counts(paths) when is_list(paths) do
    total = paths |> Enum.filter(&is_binary/1) |> Enum.uniq() |> length()
    retained = min(total, @max_files)
    %{total: total, retained: retained, omitted: total - retained}
  end

  def file_counts(_paths), do: %{total: 0, retained: 0, omitted: 0}

  # ---------------------------------------------------------------- private

  defp hash_file(path) do
    case File.read(path) do
      {:ok, content} ->
        %{
          path: path,
          sha256: :sha256 |> :crypto.hash(content) |> Base.encode16(case: :lower),
          note: nil
        }

      {:error, :enoent} ->
        %{path: path, sha256: nil, note: "no longer exists"}

      {:error, reason} ->
        %{path: path, sha256: nil, note: "unreadable (#{inspect(reason)})"}
    end
  end

  defp summary_section(nil),
    do:
      "(no summary — the previous session ended before one was written. Ask the " <>
        "operator what the goal is rather than guessing it from the files below.)"

  defp summary_section(""), do: summary_section(nil)
  defp summary_section(summary), do: String.trim(summary)

  defp files_section([], _workspace), do: "(none recorded)"

  defp files_section(files, workspace) do
    Enum.map_join(files, "\n", fn file ->
      "- `#{relative(file.path, workspace)}` — #{describe(file)}"
    end)
  end

  defp omission_section(0), do: ""

  defp omission_section(1),
    do: "\n\n(1 touched file omitted by the 200-file handoff cap; inspect the parent session.)"

  defp omission_section(count),
    do:
      "\n\n(#{count} touched files omitted by the 200-file handoff cap; inspect the parent session.)"

  defp describe(%{sha256: nil, note: note}), do: note || "unknown"
  defp describe(%{sha256: hash}), do: "sha256 " <> binary_part(hash, 0, 16)

  defp plan_section(nil), do: "(no plan was recorded)"

  defp plan_section(plan) when is_map(plan) do
    items =
      plan
      |> Map.get("plan", Map.get(plan, :plan, Map.get(plan, "items", Map.get(plan, :items, []))))
      |> List.wrap()
      |> Enum.take(@max_plan_items)

    if items == [] do
      "(no plan items were recorded)"
    else
      digest = plan_digest(items)

      "authoritative-plan-digest: sha256:#{digest}\n" <>
        Enum.map_join(items, "\n", &render_plan_item/1)
    end
  end

  defp plan_section(_plan), do: "(no plan was recorded)"

  defp instruction_section(nil),
    do:
      "The operator gave no instruction with this handoff. Say what you understand the " <>
        "state to be and ask what they want next; do not start work on a guess."

  defp instruction_section(""), do: instruction_section(nil)
  defp instruction_section(prompt), do: String.trim(prompt)

  # String-keyed first, because a plan payload comes off the wire. The atom form is only
  # tried for keys this module names itself, never for one built from a payload.
  defp value(item, key) when is_map(item) do
    Map.get(item, key) ||
      case key do
        "id" -> Map.get(item, :id)
        "status" -> Map.get(item, :status)
        "step" -> Map.get(item, :step)
        "text" -> Map.get(item, :text)
        "title" -> Map.get(item, :title)
        "work_state" -> Map.get(item, :work_state)
        "evidence" -> Map.get(item, :evidence)
        _other -> nil
      end
  end

  defp value(_item, _key), do: nil

  defp render_plan_item(item) do
    status = bounded(value(item, "status") || "pending", 32)

    text =
      bounded(value(item, "step") || value(item, "text") || value(item, "title") || "(unnamed)")

    id = value(item, "id")
    work_state = value(item, "work_state")

    metadata =
      []
      |> maybe_metadata("id", id)
      |> maybe_metadata("work_state", work_state)
      |> Enum.join(" ")

    evidence =
      item
      |> value("evidence")
      |> List.wrap()
      |> Enum.filter(&is_binary/1)
      |> Enum.take(@max_evidence_refs)
      |> Enum.map_join(", ", &bounded(&1, @max_plan_text_bytes))

    suffix =
      [
        if(metadata == "", do: nil, else: " {#{metadata}}"),
        if(evidence == "", do: nil, else: " evidence=[#{evidence}]")
      ]
      |> Enum.reject(&is_nil/1)
      |> Enum.join()

    "- [#{status}] #{text}#{suffix}"
  end

  defp maybe_metadata(parts, _name, nil), do: parts

  defp maybe_metadata(parts, name, value) when is_binary(value),
    do: parts ++ ["#{name}=#{bounded(value, 128)}"]

  defp maybe_metadata(parts, _name, _value), do: parts

  defp bounded(value, max \\ @max_plan_text_bytes)

  defp bounded(value, max) when is_binary(value) do
    value = if String.valid?(value), do: value, else: String.replace_invalid(value)
    bytes = min(byte_size(value), max)
    prefix = binary_part(value, 0, bytes)
    if String.valid?(prefix), do: prefix, else: bounded(value, bytes - 1)
  end

  defp bounded(_value, _max), do: "(invalid)"

  defp plan_digest(items) do
    items
    |> canonical()
    |> JSON.encode!()
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end

  defp canonical(value) when is_map(value) do
    value
    |> Enum.map(fn {key, nested} -> {to_string(key), canonical(nested)} end)
    |> Enum.sort_by(&elem(&1, 0))
    |> Map.new()
  end

  defp canonical(value) when is_list(value), do: Enum.map(value, &canonical/1)
  defp canonical(value) when is_atom(value), do: Atom.to_string(value)
  defp canonical(value) when is_binary(value), do: bounded(value)
  defp canonical(value) when is_number(value) or is_boolean(value) or is_nil(value), do: value
  defp canonical(_value), do: "(invalid)"

  defp relative(path, workspace) when is_binary(workspace) do
    if String.starts_with?(path, workspace <> "/"),
      do: binary_part(path, byte_size(workspace) + 1, byte_size(path) - byte_size(workspace) - 1),
      else: path
  end

  defp relative(path, _workspace), do: path
end
