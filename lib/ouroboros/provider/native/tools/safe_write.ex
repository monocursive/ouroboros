defmodule Ouroboros.Provider.Native.Tools.SafeWrite do
  @moduledoc """
  The write that closes the resolve-then-write gap, shared by every file tool.

  `Ouroboros.Provider.Native.Paths.resolve/2` proves a path is inside the workspace;
  the kernel does not remember that proof when the write happens. A process the model
  itself started can swap a leaf — or a directory on the way to it — for a symlink
  between resolve and the write, and redirect an unsandboxed BEAM write outside the
  boundary. This module narrows that gap as far as OTP allows without `O_NOFOLLOW`:

    * missing parents are created from the workspace root down, `lstat`ing every
      component so `File.mkdir_p/1` cannot follow a swapped ancestor and mkdir outside;
    * a leaf that is already a symlink is refused — the content would land where the
      link points, which is a destination this write never proved;
    * content lands in a temporary file in the target's own directory and is
      `File.rename/2`-d over the name. Rename replaces the destination link itself
      rather than following it, so a leaf swapped in after the check cannot steer the
      write;
    * after the rename the final path is canonicalized again and must still be inside
      one of the session's allowed roots;
    * replacing an existing file preserves its ordinary permission bits, so editing an
      executable does not silently turn it into a non-executable file.

  OTP has no public `openat(O_NOFOLLOW)` primitive, so a parent can still be swapped
  between its `lstat` and the temporary open. The post-write containment re-check detects
  and reports that escape, but cannot safely undo an external mutation: deleting by the
  now-escaped path would create a second race and could remove somebody else's file.
  """

  alias Ouroboros.Workspace.Path, as: WorkspacePath

  @doc """
  Writes `content` to the already-resolved `path` inside one of `scope.roots`.

  `path` must be canonical, as `Paths.resolve/2` returns it; `scope.roots` is the leased
  workspace plus its admitted `add_dirs`, which the containment re-check uses unchanged.
  """
  @spec write(String.t(), String.t(), map()) :: :ok | {:error, term()}
  def write(path, content, scope) do
    parent = Path.dirname(path)
    temporary = temporary_path(path)

    result =
      with :ok <- ensure_parent(parent, scope),
           {:ok, permissions} <- verify_leaf(path),
           :ok <- write_temporary(temporary, content),
           :ok <- preserve_permissions(temporary, permissions),
           :ok <- rename_over(temporary, path),
           :ok <- contained(path, scope) do
        :ok
      else
        {:error, reason} -> {:error, reason}
      end

    if result != :ok, do: _ = File.rm(temporary)
    result
  end

  @doc """
  Removes the already-resolved `path` if it is still a regular file inside `scope.roots`.

  `unlink` does not follow the last component, so a swapped symlink leaf would only
  remove the link. This still refuses that leaf: a name that became a link after
  resolve is the race the write path refuses, and delete is held to the same answer.
  """
  @spec delete(String.t(), map()) :: :ok | {:error, term()}
  def delete(path, scope) do
    with :ok <- ensure_deletable_parent(Path.dirname(path), scope),
         :ok <- verify_deletable(path),
         :ok <- unlink(path),
         :ok <- still_inside_or_gone(path, scope) do
      :ok
    end
  end

  # Parents are created from the matching allowed root down, never via `File.mkdir_p/1`.
  # mkdir_p follows intermediate symlinks, so a swapped ancestor would mkdir outside
  # the workspace before `verify_parent` had a chance to refuse.
  defp ensure_parent(parent, scope) do
    parent = Path.expand(parent)

    with {:ok, root} <- allowed_root(parent, scope) do
      ensure_chain(root, relative_segments(parent, root))
    else
      {:error, reason} -> {:error, {:unwritable, parent, {:containment_recheck_failed, reason}}}
    end
  end

  defp ensure_deletable_parent(parent, scope) do
    parent = Path.expand(parent)

    result =
      with {:ok, root} <- allowed_root(parent, scope) do
        verify_existing_chain(root, relative_segments(parent, root))
      else
        {:error, reason} ->
          {:error, {:unwritable, parent, {:containment_recheck_failed, reason}}}
      end

    case result do
      :ok -> :ok
      {:error, {:unwritable, path, reason}} -> {:error, {:undeletable, path, reason}}
    end
  end

  # `Paths.resolve/2` admits the workspace plus every declared `add_dirs` root. Keep
  # that exact set here: checking only `scope.root` would turn every admitted extra
  # directory into a path that resolves successfully and then inexplicably cannot be
  # written. A root must also still canonicalize to the identity captured at admission;
  # a root path replaced by a symlink is not a newly authorized location.
  defp allowed_root(path, scope) do
    candidates =
      scope
      |> Map.get(:roots, [Map.fetch!(scope, :root)])
      |> Enum.filter(&(is_binary(&1) and WorkspacePath.within?(path, &1)))
      |> Enum.sort_by(&byte_size/1, :desc)

    case Enum.find_value(candidates, fn root ->
           case WorkspacePath.canonicalize(root) do
             {:ok, ^root} -> {:ok, root}
             _moved_or_unavailable -> nil
           end
         end) do
      nil when candidates == [] -> {:error, :escaped_workspace}
      nil -> {:error, :allowed_root_moved}
      result -> result
    end
  end

  defp relative_segments(parent, root) do
    case Path.relative_to(parent, root) do
      ^parent -> []
      "." -> []
      relative -> Path.split(relative)
    end
  end

  defp ensure_chain(root, segments) do
    case verify_directory(root) do
      :ok ->
        Enum.reduce_while(segments, {:ok, root}, fn segment, {:ok, acc} ->
          next = Path.join(acc, segment)

          case ensure_component(next) do
            :ok -> {:cont, {:ok, next}}
            {:error, reason} -> {:halt, {:error, reason}}
          end
        end)
        |> case do
          {:ok, _final} -> :ok
          {:error, reason} -> {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Deletion never creates a directory. The target existed when it was resolved, so a
  # missing component now is a changed filesystem to refuse, not a parent to recreate as
  # the write path would.
  defp verify_existing_chain(root, segments) do
    case verify_directory(root) do
      :ok ->
        Enum.reduce_while(segments, {:ok, root}, fn segment, {:ok, current} ->
          next = Path.join(current, segment)

          case verify_directory(next) do
            :ok -> {:cont, {:ok, next}}
            {:error, reason} -> {:halt, {:error, reason}}
          end
        end)
        |> case do
          {:ok, _final} -> :ok
          {:error, reason} -> {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp ensure_component(path) do
    case File.lstat(path, time: :posix) do
      {:ok, %File.Stat{type: :directory}} ->
        :ok

      {:ok, %File.Stat{type: :symlink}} ->
        {:error, {:unwritable, path, :symlinked_parent}}

      {:ok, _stat} ->
        {:error, {:unwritable, path, :not_a_directory}}

      {:error, :enoent} ->
        case File.mkdir(path) do
          :ok -> verify_directory(path)
          {:error, :eexist} -> verify_directory(path)
          {:error, reason} -> {:error, {:unwritable, path, reason}}
        end

      {:error, reason} ->
        {:error, {:unwritable, path, reason}}
    end
  end

  defp verify_directory(path) do
    case File.lstat(path, time: :posix) do
      {:ok, %File.Stat{type: :directory}} -> :ok
      {:ok, %File.Stat{type: :symlink}} -> {:error, {:unwritable, path, :symlinked_parent}}
      {:ok, _stat} -> {:error, {:unwritable, path, :not_a_directory}}
      {:error, reason} -> {:error, {:unwritable, path, reason}}
    end
  end

  # A leaf that exists is allowed to be a regular file and nothing else. Renaming over
  # a symlink would stay inside the letter of containment — the link itself is replaced
  # — but a leaf that became a link after resolve is evidence of the race this module
  # exists for, and the honest answer is to refuse and let the model look at what moved.
  defp verify_leaf(path) do
    case File.lstat(path, time: :posix) do
      {:ok, %File.Stat{type: :regular, mode: mode}} -> {:ok, Bitwise.band(mode, 0o777)}
      {:error, :enoent} -> {:ok, nil}
      {:ok, %File.Stat{type: :symlink}} -> {:error, {:unwritable, path, :symlinked_leaf}}
      {:ok, _stat} -> {:error, {:unwritable, path, :not_a_regular_file}}
      {:error, reason} -> {:error, {:unwritable, path, reason}}
    end
  end

  defp verify_deletable(path) do
    case File.lstat(path, time: :posix) do
      {:ok, %File.Stat{type: :regular}} -> :ok
      {:ok, %File.Stat{type: :symlink}} -> {:error, {:undeletable, path, :symlinked_leaf}}
      {:ok, _stat} -> {:error, {:undeletable, path, :not_a_regular_file}}
      {:error, reason} -> {:error, {:undeletable, path, reason}}
    end
  end

  defp unlink(path) do
    case File.rm(path) do
      :ok -> :ok
      {:error, reason} -> {:error, {:undeletable, path, reason}}
    end
  end

  defp still_inside_or_gone(path, scope) do
    case File.lstat(path, time: :posix) do
      {:error, :enoent} ->
        ensure_deletable_parent(Path.dirname(path), scope)

      {:ok, _stat} ->
        contained(path, scope)

      {:error, reason} ->
        {:error, {:undeletable, path, {:containment_recheck_failed, reason}}}
    end
  end

  defp temporary_path(path) do
    suffix = :crypto.strong_rand_bytes(12) |> Base.url_encode64(padding: false)
    path <> ".ouro-tmp-" <> suffix
  end

  defp write_temporary(temporary, content) do
    case :file.open(String.to_charlist(temporary), [:write, :binary, :raw, :exclusive]) do
      {:ok, device} ->
        write_result = device_write(device, content)
        close_result = :file.close(device)

        case {write_result, close_result} do
          {:ok, :ok} -> :ok
          {{:error, reason}, _close} -> {:error, {:unwritable, temporary, reason}}
          {:ok, {:error, reason}} -> {:error, {:unwritable, temporary, reason}}
        end

      {:error, reason} ->
        {:error, {:unwritable, temporary, reason}}
    end
  end

  defp device_write(device, content) do
    :file.write(device, content)
  rescue
    error -> {:error, error}
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  defp preserve_permissions(_temporary, nil), do: :ok

  defp preserve_permissions(temporary, permissions) do
    case File.chmod(temporary, permissions) do
      :ok -> :ok
      {:error, reason} -> {:error, {:unwritable, temporary, reason}}
    end
  end

  defp rename_over(temporary, path) do
    case File.rename(temporary, path) do
      :ok -> :ok
      {:error, reason} -> {:error, {:unwritable, path, reason}}
    end
  end

  # The proof is repeated after the write because everything before it is check-then-use.
  # A path that no longer canonicalizes inside an admitted root is reported as a refusal.
  # Do not delete by that escaped name: an attacker could swap the external leaf again
  # between this check and `File.rm/1`, turning cleanup into an arbitrary-file deletion.
  defp contained(path, scope) do
    with {:ok, canonical} <- WorkspacePath.canonicalize_file(path),
         {:ok, _root} <- allowed_root(canonical, scope) do
      :ok
    else
      {:error, reason} ->
        {:error, {:unwritable, path, {:containment_recheck_failed, reason}}}
    end
  end

  @doc """
  A model-readable rendering of the errors `write/3` and `delete/2` can return.
  """
  @spec format_reason(term()) :: String.t()
  def format_reason({:unwritable, path, reason}), do: "#{path}: #{format_reason(reason)}"
  def format_reason({:undeletable, path, reason}), do: "#{path}: #{format_reason(reason)}"

  def format_reason(:symlinked_parent),
    do: "the file's directory was replaced by a symlink after path resolution; write refused"

  def format_reason(:symlinked_leaf),
    do: "the file was replaced by a symlink after path resolution; write refused"

  def format_reason(:not_a_directory), do: "not a directory"
  def format_reason(:not_a_regular_file), do: "not a regular file"

  def format_reason(:escaped_workspace),
    do:
      "the target moved outside the workspace between resolution and the write; the escape " <>
        "was detected after the write"

  def format_reason(:allowed_root_moved),
    do: "an allowed root moved or became a symlink after path resolution; write refused"

  def format_reason({:containment_recheck_failed, reason}),
    do: "containment re-check failed: #{inspect(reason)}"

  def format_reason(reason) when is_atom(reason), do: :file.format_error(reason)
  def format_reason(reason), do: inspect(reason)
end
