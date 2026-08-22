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
  @max_plan_items 100

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
    files = opts |> Keyword.get(:files, []) |> hash_files()
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

    #{files_section(files, workspace)}

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

  defp describe(%{sha256: nil, note: note}), do: note || "unknown"
  defp describe(%{sha256: hash}), do: "sha256 " <> binary_part(hash, 0, 16)

  defp plan_section(nil), do: "(no plan was recorded)"

  defp plan_section(plan) when is_map(plan) do
    items =
      plan
      |> Map.get("items", Map.get(plan, :items, []))
      |> List.wrap()
      |> Enum.take(@max_plan_items)

    if items == [] do
      "(no plan items were recorded)"
    else
      Enum.map_join(items, "\n", fn item ->
        status = value(item, "status") || "pending"
        text = value(item, "text") || value(item, "title") || inspect(item)
        "- [#{status}] #{text}"
      end)
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
        "status" -> Map.get(item, :status)
        "text" -> Map.get(item, :text)
        "title" -> Map.get(item, :title)
        _other -> nil
      end
  end

  defp value(_item, _key), do: nil

  defp relative(path, workspace) when is_binary(workspace) do
    if String.starts_with?(path, workspace <> "/"),
      do: binary_part(path, byte_size(workspace) + 1, byte_size(path) - byte_size(workspace) - 1),
      else: path
  end

  defp relative(path, _workspace), do: path
end
