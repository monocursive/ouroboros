defmodule Ouroboros.Provider.Native.Paths do
  @moduledoc """
  Where a native session may touch the filesystem, and where it keeps its own state.

  Containment is `Ouroboros.Workspace.Path`, which resolves symlinks one segment at a
  time and applies `..` only after each link — the reason a lexical `Path.expand/2`
  cannot be trusted here. This module adds the two things a tool loop needs on top:

    * **A path that does not exist yet.** `write` creates files. The deepest existing
      ancestor directory is canonicalized (symlinks and all) and the non-existent tail
      is appended, so a `write` through a symlinked parent is still judged by where the
      parent really is.
    * **A refusal for `..` in the request itself.** A tool argument containing a `..`
      segment is rejected before any resolution. For a path that exists the resolver
      would handle it correctly; for one that does not, `..` has no defined meaning, and
      two rules ("sometimes traversal is fine") is how a containment check grows a hole.

  Every root — the workspace and each declared `add_dirs` entry — is canonicalized
  itself. A root that cannot be canonicalized is dropped rather than trusted, which
  narrows the writable set and never widens it.
  """

  alias Ouroboros.Workspace.Path, as: WorkspacePath

  @typedoc "The resolved boundary a session's tools run inside."
  @type scope :: %{root: String.t(), roots: [String.t()], sandbox_mode: atom()}

  @doc """
  Builds the scope for a session from its workspace and declared extra directories.

  The workspace root must canonicalize; without it there is no boundary and the session
  cannot start.
  """
  @spec scope(String.t(), [String.t()], atom()) :: {:ok, scope()} | {:error, term()}
  def scope(cwd, add_dirs, sandbox_mode) do
    case WorkspacePath.canonicalize(cwd) do
      {:ok, root} ->
        extra =
          add_dirs
          |> List.wrap()
          |> Enum.flat_map(fn dir ->
            case WorkspacePath.canonicalize(dir) do
              {:ok, canonical} -> [canonical]
              {:error, _reason} -> []
            end
          end)

        {:ok,
         %{
           root: root,
           roots: Enum.uniq([root | extra]),
           sandbox_mode: sandbox_mode
         }}

      {:error, reason} ->
        {:error, {:workspace_unavailable, reason}}
    end
  end

  @doc """
  Resolves one tool path against a scope, or says why it is refused.

  Relative paths are joined to the workspace root. The result is always absolute and
  canonical, and always inside one of the scope's roots.
  """
  @spec resolve(term(), scope()) :: {:ok, String.t()} | {:error, term()}
  def resolve(path, scope) when is_binary(path) and path != "" do
    with :ok <- reject_traversal(path),
         absolute = absolutize(path, scope.root),
         {:ok, canonical} <- canonicalize(absolute),
         :ok <- contained(canonical, scope) do
      {:ok, canonical}
    end
  end

  def resolve(path, _scope), do: {:error, {:invalid_path, inspect(path)}}

  @doc "A human-readable refusal, safe to hand back to the model as a tool result."
  @spec describe_error(term()) :: String.t()
  def describe_error({:path_escapes_workspace, path, roots}),
    do:
      "#{path} is outside this session's workspace. Allowed roots: " <>
        Enum.join(roots, ", ") <> "."

  def describe_error({:path_traversal, path}),
    do: "#{path} contains a `..` segment. Give an absolute path inside the workspace."

  def describe_error({:invalid_path, path}), do: "#{path} is not a usable path."

  def describe_error({:workspace_unavailable, reason}),
    do: "the session workspace could not be resolved: #{inspect(reason)}"

  def describe_error({:path_unresolvable, path, reason}),
    do: "#{path} could not be resolved: #{inspect(reason)}"

  def describe_error(reason), do: inspect(reason)

  @doc """
  The private directory this session owns for spill files and its checkpoint.

  `<data_dir>/native/<session>` when this node has a durable data directory, and a
  directory under the system temp root when it does not. The second case is honest
  rather than fatal: bash spill files still work, and the checkpoint is written but
  does not survive a reboot — which `Ouroboros.Provider.Native.Checkpoint` reports as
  `durable?: false` instead of implying a resume that will not be there.
  """
  @spec session_dir(String.t()) :: {:ok, String.t(), boolean()} | {:error, term()}
  def session_dir(provider_session_id) do
    with :ok <- validate_session_id(provider_session_id),
         {root, durable?} <- root_dir(),
         path = Path.join(root, provider_session_id),
         :ok <- mkdir_private(root),
         :ok <- mkdir_private(path) do
      {:ok, path, durable?}
    else
      {:error, _reason} = error -> error
    end
  end

  @doc """
  Refuses a `provider_session_id` that is not this provider's own shape.

  The id becomes a directory name. A caller-supplied value reaches this function on the
  resume path, so it is checked as untrusted input, not decorated.
  """
  @spec validate_session_id(term()) :: :ok | {:error, term()}
  def validate_session_id(id) when is_binary(id) do
    if Regex.match?(~r/\Anative-[A-Za-z0-9_-]{1,64}-[A-Za-z0-9_-]{1,64}\z/, id),
      do: :ok,
      else: {:error, {:invalid_provider_session_id, id}}
  end

  def validate_session_id(id), do: {:error, {:invalid_provider_session_id, inspect(id)}}

  @doc """
  A fresh native session id that embeds this node.

  Every cluster-visible namespace in this runtime derives from `node()`; a random id
  alone would collide the moment two nodes' journals met.
  """
  @spec new_session_id() :: String.t()
  def new_session_id do
    node_tag =
      :sha256
      |> :crypto.hash(Atom.to_string(node()))
      |> Base.url_encode64(padding: false)
      |> binary_part(0, 12)

    random = Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)
    "native-" <> node_tag <> "-" <> random
  end

  defp root_dir do
    case Application.get_env(:ouroboros, :native_data_dir) do
      path when is_binary(path) and path != "" ->
        {path, true}

      _unset ->
        case Application.get_env(:ouroboros, :data_dir) do
          path when is_binary(path) and path != "" ->
            {Path.join(path, "native"), true}

          _unset ->
            {Path.join(System.tmp_dir!(), "ouroboros-native-#{:erlang.phash2(node())}"), false}
        end
    end
  end

  defp mkdir_private(path) do
    case File.mkdir_p(path) do
      :ok ->
        _ = File.chmod(path, 0o700)
        :ok

      {:error, reason} ->
        {:error, {:session_dir_unavailable, path, reason}}
    end
  end

  defp reject_traversal(path) do
    if ".." in Path.split(path), do: {:error, {:path_traversal, path}}, else: :ok
  end

  defp absolutize(path, root) do
    if Path.type(path) == :absolute, do: path, else: Path.join(root, path)
  end

  defp canonicalize(absolute) do
    cond do
      File.dir?(absolute) ->
        WorkspacePath.canonicalize(absolute)

      File.regular?(absolute) ->
        WorkspacePath.canonicalize_file(absolute)

      true ->
        canonicalize_new(absolute)
    end
    |> case do
      {:ok, canonical} -> {:ok, canonical}
      {:error, reason} -> {:error, {:path_unresolvable, absolute, reason}}
    end
  end

  # A leaf that does not exist yet. Resolve the deepest ancestor that does — through
  # every symlink on the way — and re-attach the missing tail.
  defp canonicalize_new(absolute) do
    {parent, tail} = deepest_existing(absolute, [])

    case WorkspacePath.canonicalize(parent) do
      {:ok, canonical} -> {:ok, Path.join([canonical | tail])}
      {:error, _reason} = error -> error
    end
  end

  defp deepest_existing(path, tail) do
    parent = Path.dirname(path)
    base = Path.basename(path)

    cond do
      parent == path -> {"/", tail}
      File.dir?(parent) -> {parent, [base | tail]}
      true -> deepest_existing(parent, [base | tail])
    end
  end

  defp contained(canonical, scope) do
    if Enum.any?(scope.roots, &WorkspacePath.within?(canonical, &1)),
      do: :ok,
      else: {:error, {:path_escapes_workspace, canonical, scope.roots}}
  end
end
