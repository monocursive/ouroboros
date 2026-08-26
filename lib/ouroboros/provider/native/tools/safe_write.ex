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
      the workspace; an escape removes the written file and fails.

  The residual window — a parent swapped between its lstat and the temporary open — is
  microseconds, and the post-write containment re-check is what catches it.
  """

  alias Ouroboros.Workspace.Path, as: WorkspacePath

  @doc """
  Writes `content` to the already-resolved `path` inside `scope.root`.

  `path` must be canonical, as `Paths.resolve/2` returns it; `scope.root` is the leased
  workspace root the containment re-check is measured against.
  """
  @spec write(String.t(), String.t(), map()) :: :ok | {:error, term()}
  def write(path, content, scope) do
    parent = Path.dirname(path)
    temporary = temporary_path(path)

    result =
      with :ok <- ensure_parent(parent, scope),
           :ok <- verify_leaf(path),
           :ok <- write_temporary(temporary, content),
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
  Removes the already-resolved `path` if it is still a regular file inside `scope.root`.

  `unlink` does not follow the last component, so a swapped symlink leaf would only
  remove the link. This still refuses that leaf: a name that became a link after
  resolve is the race the write path refuses, and delete is held to the same answer.
  """
  @spec delete(String.t(), map()) :: :ok | {:error, term()}
  def delete(path, scope) do
    with :ok <- verify_deletable(path),
         :ok <- unlink(path),
         :ok <- still_inside_or_gone(path, scope) do
      :ok
    end
  end

  # Parents are created from the workspace root down, never via `File.mkdir_p/1`.
  # mkdir_p follows intermediate symlinks, so a swapped ancestor would mkdir outside
  # the workspace before `verify_parent` had a chance to refuse.
  defp ensure_parent(parent, scope) do
    with {:ok, root} <- WorkspacePath.canonicalize(scope.root),
         parent = Path.expand(parent),
         true <- WorkspacePath.within?(parent, root) do
      ensure_chain(root, relative_segments(parent, root))
    else
      false -> {:error, {:unwritable, parent, :escaped_workspace}}
      {:error, reason} -> {:error, {:unwritable, parent, {:containment_recheck_failed, reason}}}
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
      {:ok, %File.Stat{type: :regular}} -> :ok
      {:error, :enoent} -> :ok
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
        :ok

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
    with {:ok, device} <-
           :file.open(String.to_charlist(temporary), [:write, :binary, :raw, :exclusive]),
         :ok <- :file.write(device, content),
         :ok <- :file.close(device) do
      :ok
    else
      {:error, reason} -> {:error, {:unwritable, temporary, reason}}
    end
  rescue
    error -> {:error, {:unwritable, temporary, error}}
  end

  defp rename_over(temporary, path) do
    case File.rename(temporary, path) do
      :ok -> :ok
      {:error, reason} -> {:error, {:unwritable, path, reason}}
    end
  end

  # The proof is repeated after the write because everything before it is check-then-use.
  # A path that no longer canonicalizes inside the workspace is removed best-effort and
  # reported as a refusal, because its bytes may already be somewhere they were never
  # admitted.
  defp contained(path, scope) do
    with {:ok, root} <- WorkspacePath.canonicalize(scope.root),
         {:ok, canonical} <- WorkspacePath.canonicalize_file(path) do
      if WorkspacePath.within?(canonical, root) do
        :ok
      else
        _ = File.rm(path)
        {:error, {:unwritable, path, :escaped_workspace}}
      end
    else
      {:error, reason} ->
        _ = File.rm(path)
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
      "the target moved outside the workspace between resolution and the write; the write " <>
        "was removed"

  def format_reason({:containment_recheck_failed, reason}),
    do: "containment re-check failed: #{inspect(reason)}"

  def format_reason(reason) when is_atom(reason), do: :file.format_error(reason)
  def format_reason(reason), do: inspect(reason)
end
