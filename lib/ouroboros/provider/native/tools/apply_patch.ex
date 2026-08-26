defmodule Ouroboros.Provider.Native.Tools.ApplyPatch do
  @moduledoc """
  Apply one V4A patch across several files, atomically or not at all.

  `edit` changes one string in one file; this changes a set of files in one call, which
  is what a rename-plus-callers or a new-module-plus-registration actually is. Codex's
  format is used unchanged (`Ouroboros.Provider.Native.Tools.Patch`) because it is the
  one the models that emit patches have been trained on, and inventing a fourth edit
  format would be a tax on every provider that already speaks this one.

  ## The same guards as `edit`, for the same reasons

  A file an `*** Update File:` or `*** Delete File:` section touches must have been
  `read` in this session and must not have changed since that read. Those two checks are
  the ones with published failure modes (R3 §1.2), and a multi-file edit is exactly
  where a stale read does the most damage.

  ## Atomic across the patch

  Every section is resolved against the current files first — parsed, contained,
  guarded, and applied *in memory* — and nothing is written until all of them succeed.
  A patch that fails on its third file leaves the first two untouched. That is not
  convenience; a half-applied patch is a tree in a state no one described and the model
  cannot reason about, and the format's own envelope says the sections belong together.

  Writing itself is not transactional — three `SafeWrite.write/3` calls are three
  syscalls — so a disk that fails between them is reported by naming which files were written and
  which were not. Every file written before that point is in the session's checkpoint
  and can be rewound.

  ## One `file_change` per file

  Each section produces its own `changes` entry with its own unified diff, so a client
  renders three files as three diffs rather than one blob, and the checkpoint records
  three restorable paths.
  """

  use Jido.Action,
    name: "apply_patch",
    description:
      "Apply a V4A patch (`*** Begin Patch` … `*** End Patch`) that adds, updates, " <>
        "moves or deletes several files at once. Read every file you update first. " <>
        "Prefer `edit` for a single change to a single file.",
    schema: [
      patch: [
        type: :string,
        required: true,
        doc:
          "The complete patch, starting with `*** Begin Patch` and ending with " <>
            "`*** End Patch`. Sections are `*** Add File: <path>`, " <>
            "`*** Delete File: <path>`, and `*** Update File: <path>` with optional " <>
            "`*** Move to: <path>`; hunks start with `@@` and their lines are prefixed " <>
            "with a space, `-`, or `+`. No line numbers."
      ]
    ]

  alias Ouroboros.Provider.Native.Diff
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Tools.{Patch, Read, SafeWrite}

  @similar_lines 3

  @impl true
  def run(params, context) do
    with :ok <- writable(context.scope),
         {:ok, files} <- Patch.parse(params.patch),
         {:ok, plans} <- plan(files, context) do
      commit(plans, context)
    else
      {:error, reason} ->
        {:ok, %{output: "apply_patch failed: #{describe(reason)}", is_error: true}}
    end
  end

  @doc """
  Every workspace path a patch would touch, resolved, for the permission engine.

  Called by `Ouroboros.Provider.Native.Tools.classify/3` before the gate runs and by the
  loop before it snapshots. A patch that will not parse reports no paths — the engine
  still sees an `apply_patch` in `:write` mode and the tool refuses it a moment later.
  """
  @spec paths(map(), map()) :: [String.t()]
  def paths(input, scope) do
    with patch when is_binary(patch) <- Map.get(input, "patch"),
         {:ok, files} <- Patch.parse(patch) do
      files
      |> Patch.paths()
      |> Enum.flat_map(fn path ->
        case Paths.resolve(path, scope) do
          {:ok, resolved} -> [resolved]
          {:error, _refused} -> [path]
        end
      end)
      |> Enum.uniq()
    else
      _unusable -> []
    end
  end

  # ---------------------------------------------------------------- planning

  defp writable(%{sandbox_mode: :read_only}), do: {:error, :read_only_sandbox}
  defp writable(_scope), do: :ok

  defp plan(files, context) do
    Enum.reduce_while(files, {:ok, []}, fn file, {:ok, acc} ->
      case plan_one(file, context) do
        {:ok, planned} -> {:cont, {:ok, acc ++ planned}}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
  end

  defp plan_one(%Patch.FileOp{kind: :add} = file, context) do
    with {:ok, path} <- Paths.resolve(file.path, context.scope),
         :ok <- absent(path) do
      {:ok, [%{action: :write, path: path, before: nil, after: file.content, kind: :add}]}
    end
  end

  defp plan_one(%Patch.FileOp{kind: :delete} = file, context) do
    with {:ok, path} <- Paths.resolve(file.path, context.scope),
         {:ok, content} <- read(path),
         :ok <- guarded(path, content, context) do
      {:ok, [%{action: :delete, path: path, before: content, after: nil, kind: :delete}]}
    end
  end

  defp plan_one(%Patch.FileOp{kind: :update} = file, context) do
    with {:ok, path} <- Paths.resolve(file.path, context.scope),
         {:ok, content} <- read(path),
         :ok <- guarded(path, content, context),
         {:ok, updated, tier} <- apply_hunks(content, file, path) do
      case file.move_to do
        nil ->
          {:ok,
           [
             %{
               action: :write,
               path: path,
               before: content,
               after: updated,
               kind: :modify,
               tier: tier
             }
           ]}

        target ->
          with {:ok, moved} <- Paths.resolve(target, context.scope),
               :ok <- absent_or_same(moved, path) do
            {:ok,
             [
               %{action: :delete, path: path, before: content, after: nil, kind: :delete},
               %{
                 action: :write,
                 path: moved,
                 before: nil,
                 after: updated,
                 kind: :add,
                 tier: tier
               }
             ]}
          end
      end
    end
  end

  defp apply_hunks(content, file, path) do
    case Patch.apply_hunks(content, file) do
      {:ok, updated, tier} -> {:ok, updated, tier}
      {:error, {:hunk_not_found, hunk, needle}} -> {:error, {:hunk_not_found, path, hunk, needle}}
      {:error, _reason} = error -> error
    end
  end

  defp read(path) do
    case File.read(path) do
      {:ok, content} -> {:ok, content}
      {:error, :enoent} -> {:error, {:missing_file, path}}
      {:error, reason} -> {:error, {:unreadable, path, reason}}
    end
  end

  defp absent(path) do
    if File.exists?(path), do: {:error, {:already_exists, path}}, else: :ok
  end

  defp absent_or_same(target, source) do
    if target == source or not File.exists?(target),
      do: :ok,
      else: {:error, {:move_target_exists, target}}
  end

  # Identical to `Edit`'s pair of guards, deliberately: two spellings of read-before-edit
  # is how one of them drifts into being weaker than the other.
  defp guarded(path, content, context) do
    case Map.get(context.reads || %{}, path) do
      %{hash: recorded} ->
        case File.stat(path, time: :posix) do
          {:ok, stat} ->
            if Read.fingerprint(stat, content).hash == recorded,
              do: :ok,
              else: {:error, {:modified_since_read, path}}

          {:error, reason} ->
            {:error, {:unreadable, path, reason}}
        end

      _never_read ->
        {:error, {:not_read, path}}
    end
  end

  # ---------------------------------------------------------------- commit

  defp commit(plans, context) do
    {written, failure} =
      Enum.reduce_while(plans, {[], nil}, fn plan, {done, nil} ->
        case perform(plan, context.scope) do
          :ok -> {:cont, {[plan | done], nil}}
          {:error, reason} -> {:halt, {done, {plan, reason}}}
        end
      end)

    done = Enum.reverse(written)
    root = context.scope.root

    result = %{
      output: summary(done, failure, root),
      is_error: failure != nil,
      changes: Enum.map(done, &change(&1, root)),
      reads: Map.new(done, &{&1.path, fingerprint(&1)}) |> Map.reject(fn {_k, v} -> is_nil(v) end)
    }

    {:ok, result}
  end

  defp perform(%{action: :write, path: path, after: content}, scope) do
    case SafeWrite.write(path, content, scope) do
      :ok -> :ok
      {:error, {:unwritable, _path, _reason} = error} -> {:error, error}
    end
  end

  defp perform(%{action: :delete, path: path}, scope) do
    case SafeWrite.delete(path, scope) do
      :ok -> :ok
      {:error, {:undeletable, _path, _reason} = error} -> {:error, error}
    end
  end

  defp change(plan, root),
    do:
      Diff.change(
        plan.path,
        Path.relative_to(plan.path, root),
        plan.before,
        plan.after,
        plan.kind
      )

  defp fingerprint(%{action: :delete}), do: nil

  defp fingerprint(%{path: path}) do
    case Read.fingerprint(path) do
      {:ok, fingerprint} -> fingerprint
      {:error, _reason} -> nil
    end
  end

  defp summary([], nil, _root), do: "The patch touched no files."

  defp summary(done, nil, root) do
    tiers = done |> Enum.map(&Map.get(&1, :tier)) |> Enum.reject(&is_nil/1) |> Enum.uniq()

    note =
      cond do
        :indentation in tiers ->
          " Some hunks matched with indentation ignored, not byte-for-byte."

        :trailing_whitespace in tiers ->
          " Some hunks matched with trailing whitespace ignored, not byte-for-byte."

        true ->
          ""
      end

    "Applied the patch to #{length(done)} #{plural(length(done))}:\n" <>
      Enum.map_join(done, "\n", &("  " <> verb(&1) <> " " <> Path.relative_to(&1.path, root))) <>
      note
  end

  defp summary(done, {plan, reason}, root) do
    header = "apply_patch failed partway: #{describe(reason)}"

    written =
      if done == [],
        do: "\nNothing was written.",
        else:
          "\nThese files were already written and are in the session checkpoint:\n" <>
            Enum.map_join(done, "\n", &("  " <> Path.relative_to(&1.path, root)))

    header <> "\nIt stopped at #{Path.relative_to(plan.path, root)}." <> written
  end

  defp verb(%{action: :delete}), do: "deleted"
  defp verb(%{kind: :add}), do: "added"
  defp verb(_plan), do: "updated"

  defp plural(1), do: "file"
  defp plural(_count), do: "files"

  # ---------------------------------------------------------------- refusals

  defp describe(:read_only_sandbox),
    do: "this session runs with sandbox_mode: read_only, which refuses every write"

  defp describe({:already_exists, path}),
    do: "#{path} already exists; `*** Add File:` only creates. Use `*** Update File:`."

  defp describe({:move_target_exists, path}), do: "#{path} already exists, so nothing was moved"
  defp describe({:missing_file, path}), do: "#{path} does not exist"

  defp describe({:not_read, path}),
    do: "#{path} has not been read in this session. Call `read` on it first."

  defp describe({:modified_since_read, path}),
    do:
      "#{path} changed since it was read. Read it again, then re-issue the patch against " <>
        "the current content."

  defp describe({:hunk_not_found, path, hunk, needle}), do: hunk_message(path, hunk, needle)
  defp describe({:unreadable, path, reason}), do: "#{path}: #{:file.format_error(reason)}"
  defp describe({:unwritable, _path, _reason} = error), do: SafeWrite.format_reason(error)
  defp describe({:undeletable, _path, _reason} = error), do: SafeWrite.format_reason(error)
  defp describe(reason), do: patch_or_path(reason)

  defp patch_or_path(reason) do
    described = Patch.describe(reason)
    if described == inspect(reason), do: Paths.describe_error(reason), else: described
  end

  # Aider's `find_similar_lines`, applied to a hunk: naming the lines the file actually
  # has is what turns the retry into a correction instead of a re-roll.
  defp hunk_message(path, hunk, needle) do
    anchor = Enum.find(needle, "", &(String.trim(&1) != ""))

    similar =
      case File.read(path) do
        {:ok, content} -> similar_lines(content, anchor)
        {:error, _reason} -> []
      end

    scope =
      case hunk.markers do
        [] -> ""
        markers -> " (under `@@ " <> Enum.join(markers, "` / `@@ ") <> "`)"
      end

    base =
      "a hunk's context was not found in #{path}#{scope}, in any whitespace tier.\n" <>
        "The hunk expected:\n" <>
        (needle |> Enum.take(6) |> Enum.map_join("\n", &("  " <> &1)))

    case similar do
      [] -> base
      lines -> base <> "\nClosest lines in the file:\n" <> Enum.join(lines, "\n")
    end
  end

  defp similar_lines(_content, ""), do: []

  defp similar_lines(content, anchor) do
    target = String.trim(anchor)

    content
    |> String.split("\n")
    |> Enum.with_index(1)
    |> Enum.map(fn {line, number} ->
      {String.jaro_distance(String.trim(line), target), number, line}
    end)
    |> Enum.filter(fn {score, _number, _line} -> score > 0.7 end)
    |> Enum.sort_by(fn {score, _number, _line} -> -score end)
    |> Enum.take(@similar_lines)
    |> Enum.map(fn {_score, number, line} -> "  #{number}: #{line}" end)
  end
end
