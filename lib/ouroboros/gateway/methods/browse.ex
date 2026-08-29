defmodule Ouroboros.Gateway.Methods.Browse do
  @moduledoc false

  # D11 / docs/WEB.md §7. The one filesystem answer this gateway gives, and the reason it
  # exists: a client that has to pick a workspace before it can start a session would
  # otherwise need a second channel to the disk. So the surface is one directory listing,
  # narrowed until there is nothing in it worth attacking.
  #
  # ## What "inside the roots" means here
  #
  # The roots are `$HOME` and `:workspace_allowed_roots`, each *canonicalized* — every
  # symlink resolved, `..` applied only after each preceding link, and the result stat'd as
  # a directory (`Ouroboros.Workspace.Path.canonicalize/1`, the same resolver that
  # authorizes a workspace lease). A root that does not resolve is dropped rather than
  # carried: a root nothing can be inside of is not a root, and listing it would promise a
  # place this node cannot go.
  #
  # A requested path is canonicalized the same way and then held to a prefix check against
  # those canonical roots. That is what makes `..` and a symlink pointing out of a root the
  # same refusal rather than two: both are resolved before anything is compared, so neither
  # can arrive at a different answer than the filesystem would give. Nothing is resolved
  # against `File.cwd/0` — a relative path is refused rather than interpreted, because the
  # daemon's working directory is not a place a client can see or reason about.
  #
  # ## What a refusal is allowed to say
  #
  # A path outside every root is told *that*, and nothing else. Whether it exists, whether
  # it is a directory, and what it resolves to are facts about a filesystem this method
  # does not serve, and answering them would turn a directory picker into a probe. That
  # rule survives the awkward case — a path that does not resolve at all — because
  # containment is then decided from its nearest *existing* ancestor
  # (`ancestor_contained?/2`) rather than from the failure: `/etc/nope` and
  # `<root>/link-to-etc/nope` are both "outside the roots", and only a path whose real
  # parent is inside a root gets told the true reason.
  #
  # ## What an entry is
  #
  # Directories only, dotfiles excluded, name-sorted by byte order, and every one of them
  # openable: an entry that is a symlink out of the roots is left out, because listing a
  # row the very next call refuses is a lie a picker tells. The list is bounded at
  # `@limit`, and a list that was cut says so — a silent cap is the failure mode this
  # repository does not ship.

  alias Ouroboros.Workspace.Path, as: WorkspacePath

  # Chosen to match the gateway's other window bound (`@replay_limit`). A home directory
  # with more than five hundred visible subdirectories is real; a picker that scrolled all
  # of them is not, and `truncated` is how the client says so out loud.
  @limit 500

  @typedoc """
  Why a listing was refused. The tag is the wire's `data.reason`; the map carries only what
  the caller is entitled to see.
  """
  @type refusal ::
          {:no_browse_roots, map()}
          | {:relative_path, map()}
          | {:outside_roots, %{roots: [String.t()]}}
          | {:no_such_directory, map()}
          | {:not_a_directory, map()}
          | {:unreadable, %{detail: String.t()}}

  @doc "The bound on one listing, so the parameter contract and the walker cannot disagree."
  @spec limit() :: pos_integer()
  def limit, do: @limit

  @doc """
  Every directory this node browses, canonical, in the order a client should offer them.

  `$HOME` first because it is where a person's work is, then `:workspace_allowed_roots` in
  the order the operator configured them. Duplicates collapse to their first appearance and
  a root that does not resolve to a directory is dropped.
  """
  @spec roots() :: [String.t()]
  def roots do
    [System.get_env("HOME") | configured_roots()]
    |> Enum.filter(&(is_binary(&1) and &1 != ""))
    |> Enum.flat_map(fn root ->
      case WorkspacePath.canonicalize(root) do
        {:ok, canonical} -> [canonical]
        {:error, _reason} -> []
      end
    end)
    |> Enum.uniq()
  end

  @doc """
  One directory listing, or the typed refusal that says why there is none.

  `nil` asks for the browse root, which is the first entry of `roots/0`.
  """
  @spec browse(String.t() | nil) :: {:ok, map()} | {:error, refusal()}
  def browse(path) do
    case roots() do
      [] -> {:error, {:no_browse_roots, %{}}}
      [default | _rest] = roots -> resolve_and_list(path || default, roots)
    end
  end

  # ---------------------------------------------------------------------------

  defp configured_roots do
    :ouroboros
    |> Application.get_env(:workspace_allowed_roots, [])
    |> List.wrap()
  end

  defp resolve_and_list(path, roots) do
    if Path.type(path) == :absolute do
      case WorkspacePath.canonicalize(path) do
        {:ok, canonical} ->
          if within_any?(canonical, roots),
            do: list(canonical, roots),
            else: outside(roots)

        {:error, reason} ->
          # The failure is only allowed to be reported where the caller was already
          # entitled to look. Containment is decided from the nearest ancestor that does
          # resolve, so a name under a directory this node does not browse is "outside the
          # roots" whether it exists or not.
          if ancestor_contained?(path, roots),
            do: {:error, failure(reason)},
            else: outside(roots)
      end
    else
      {:error, {:relative_path, %{}}}
    end
  end

  defp outside(roots), do: {:error, {:outside_roots, %{roots: roots}}}

  defp list(directory, roots) do
    case File.ls(directory) do
      {:ok, names} ->
        {shown, rest} =
          names
          |> Enum.reject(&String.starts_with?(&1, "."))
          |> Enum.filter(&openable_directory?(Path.join(directory, &1), roots))
          |> Enum.sort()
          |> Enum.split(@limit)

        {:ok,
         %{
           "path" => directory,
           "parent" => parent(directory, roots),
           "roots" => roots,
           "entries" => Enum.map(shown, &%{"name" => &1, "dir" => true}),
           "truncated" => rest != []
         }}

      {:error, reason} ->
        {:error, unreadable(reason)}
    end
  end

  # `directory` is canonical, so a real subdirectory of it is canonical too and inherits
  # its containment; only a link has to be resolved and re-checked. A dangling link, a
  # regular file, and a device are all "not a directory a client can open".
  defp openable_directory?(path, roots) do
    case File.lstat(path) do
      {:ok, %File.Stat{type: :directory}} ->
        true

      {:ok, %File.Stat{type: :symlink}} ->
        case WorkspacePath.canonicalize(path) do
          {:ok, canonical} -> within_any?(canonical, roots)
          {:error, _reason} -> false
        end

      _other ->
        false
    end
  end

  # Never above a root, and never past the filesystem's own top. A root whose parent is
  # itself inside another configured root still leads upward, because that parent is a
  # place this node browses; a root with nothing above it answers `null`, which is what a
  # client draws as "you are at the top".
  defp parent(directory, roots) do
    above = Path.dirname(directory)

    if above != directory and within_any?(above, roots), do: above, else: nil
  end

  defp within_any?(path, roots), do: Enum.any?(roots, &WorkspacePath.within?(path, &1))

  defp ancestor_contained?(path, roots) do
    above = Path.dirname(path)

    if above == path do
      false
    else
      case WorkspacePath.canonicalize(above) do
        {:ok, canonical} -> within_any?(canonical, roots)
        {:error, _reason} -> ancestor_contained?(above, roots)
      end
    end
  end

  # The candidate path each of these carries is deliberately dropped: it is either the one
  # the caller sent, which it already has, or what a symlink resolved to, which is the one
  # thing a containment failure exists to keep quiet about.
  defp failure({:path_unavailable, _candidate, :enoent}), do: {:no_such_directory, %{}}
  defp failure({:path_unavailable, _candidate, :enotdir}), do: {:not_a_directory, %{}}
  defp failure({:not_a_directory, _candidate}), do: {:not_a_directory, %{}}
  defp failure({:path_unavailable, _candidate, reason}), do: unreadable(reason)
  defp failure({:symbolic_link_unreadable, _candidate, reason}), do: unreadable(reason)
  defp failure({:symbolic_link_cycle, _candidate}), do: unreadable(:symbolic_link_cycle)
  defp failure(:too_many_symbolic_links), do: unreadable(:too_many_symbolic_links)
  defp failure({:workspace_path_error, _path, reason}), do: unreadable(reason)
  defp failure(reason), do: unreadable(reason)

  defp unreadable(reason) when is_atom(reason) or is_binary(reason),
    do: {:unreadable, %{detail: to_string(reason)}}

  defp unreadable(reason), do: {:unreadable, %{detail: inspect(reason)}}
end
