defmodule Ouroboros.Control.Permissions.Paths do
  @moduledoc """
  Path canonicalisation and glob matching for the permission engine.

  Canonicalisation is `Ouroboros.Workspace.Path`'s, deliberately: the symlink-following
  resolver that already decides what is inside a leased workspace is the one that decides
  what a `Write(…)` rule and a protected path apply to. Using a second, lexical notion of
  "the same file" here would mean a rule and a lease could disagree about one path.

  The one thing this module adds is that a permission is asked about a file that **does
  not exist yet** — that is what a write is. `canonicalize/2` resolves the nearest
  existing ancestor through `Workspace.Path.canonicalize/1` and appends the remaining
  segments lexically, so a new file inside a symlinked directory canonicalises to the
  same place the eventual write lands.

  Globs are the usual shell shapes, compiled to an anchored regex:

      *    any run of characters inside one path segment
      **   any run of characters across segments
      ?    exactly one character that is not a separator

  A relative glob is resolved against the workspace root before it is compiled, so
  `Write(src/**)` in a workspace rule means that workspace's `src`, never another's.
  """

  alias Ouroboros.Workspace.Path, as: WorkspacePath

  @max_ancestor_walk 64

  @doc """
  Canonicalises one path, resolving symlinks as far as the filesystem allows.

  A relative path is resolved against `root` when one is given, and against the current
  working directory otherwise. A path whose ancestors cannot be resolved at all is
  returned lexically normalised — an unresolvable path is still something a rule and the
  protected-path list must be able to answer about, and answering "I could not tell" for
  a write into `.git` would fail open.
  """
  @spec canonicalize(String.t(), String.t() | nil) :: {:ok, String.t()} | {:error, term()}
  def canonicalize(path, root \\ nil)

  def canonicalize(path, root) when is_binary(path) and path != "" do
    absolute =
      cond do
        Path.type(path) == :absolute -> path
        is_binary(root) and root != "" -> Path.join(root, path)
        true -> Path.expand(path)
      end

    {:ok, resolve(absolute)}
  end

  def canonicalize(path, _root), do: {:error, {:invalid_path, path}}

  @doc "Whether `path` is `root` or lives under it. Both must already be canonical."
  @spec within?(String.t(), String.t()) :: boolean()
  def within?(path, root) when is_binary(path) and is_binary(root),
    do: WorkspacePath.within?(path, root)

  def within?(_path, _root), do: false

  @doc "Whether any segment of `path` is exactly `segment`."
  @spec has_segment?(String.t(), String.t()) :: boolean()
  def has_segment?(path, segment) when is_binary(path) and is_binary(segment) do
    path |> String.split("/", trim: true) |> Enum.member?(segment)
  end

  def has_segment?(_path, _segment), do: false

  @doc """
  Whether a canonical `path` matches `glob`, itself resolved against `root` when relative.
  """
  @spec matches_glob?(String.t(), String.t(), String.t() | nil) :: boolean()
  def matches_glob?(path, glob, root \\ nil)

  def matches_glob?(path, glob, root) when is_binary(path) and is_binary(glob) do
    absolute_glob =
      cond do
        Path.type(glob) == :absolute -> glob
        String.starts_with?(glob, "~/") -> Path.join(home(), String.trim_leading(glob, "~/"))
        is_binary(root) and root != "" -> Path.join(root, glob)
        # A bare glob with no root to hang it on matches on any suffix of the path, which
        # is what `Read(*.env)` has to mean when nobody said where.
        true -> "**/" <> glob
      end

    Regex.match?(compile(absolute_glob), path)
  end

  def matches_glob?(_path, _glob, _root), do: false

  @doc "Compiles a glob into the anchored regex `matches_glob?/3` uses. Exposed for tests."
  @spec compile(String.t()) :: Regex.t()
  def compile(glob) do
    Regex.compile!("\\A" <> translate(glob, "") <> "\\z")
  end

  defp translate(<<>>, acc), do: acc

  defp translate(<<"**/", rest::binary>>, acc), do: translate(rest, acc <> "(?:.*/)?")
  defp translate(<<"**", rest::binary>>, acc), do: translate(rest, acc <> ".*")
  defp translate(<<"*", rest::binary>>, acc), do: translate(rest, acc <> "[^/]*")
  defp translate(<<"?", rest::binary>>, acc), do: translate(rest, acc <> "[^/]")

  defp translate(<<char::utf8, rest::binary>>, acc) do
    translate(rest, acc <> Regex.escape(<<char::utf8>>))
  end

  # Walk up to the nearest ancestor the resolver accepts, then re-attach what was missing.
  defp resolve(absolute) do
    case walk(absolute, [], @max_ancestor_walk) do
      {:ok, canonical, []} ->
        canonical

      {:ok, canonical, suffix} ->
        [canonical | suffix]
        |> Path.join()
        |> Path.expand()

      :error ->
        Path.expand(absolute)
    end
  end

  defp walk(_candidate, _suffix, 0), do: :error
  defp walk("/", suffix, _budget), do: {:ok, "/", suffix}

  defp walk(candidate, suffix, budget) do
    case WorkspacePath.canonicalize(candidate) do
      {:ok, canonical} ->
        {:ok, canonical, suffix}

      {:error, _reason} ->
        case WorkspacePath.canonicalize_file(candidate) do
          {:ok, canonical} ->
            {:ok, canonical, suffix}

          {:error, _reason} ->
            parent = Path.dirname(candidate)

            if parent == candidate,
              do: :error,
              else: walk(parent, [Path.basename(candidate) | suffix], budget - 1)
        end
    end
  end

  defp home, do: System.user_home() || "/"
end
