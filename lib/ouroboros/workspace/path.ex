defmodule Ouroboros.Workspace.Path do
  @moduledoc false

  @max_symlinks 64

  @spec canonicalize(String.t()) :: {:ok, String.t()} | {:error, term()}
  def canonicalize(path) when is_binary(path) and byte_size(path) > 0 do
    with {:ok, absolute} <- make_absolute(path),
         {:ok, canonical} <- resolve("/", split(absolute), %{}, 0),
         {:ok, %File.Stat{type: :directory}} <- File.stat(canonical) do
      {:ok, canonical}
    else
      {:ok, %File.Stat{}} -> {:error, {:not_a_directory, path}}
      {:error, reason} -> {:error, normalize_file_error(reason, path)}
    end
  end

  def canonicalize(path), do: {:error, {:invalid_workspace_path, path}}

  @doc false
  @spec canonicalize_file(String.t()) :: {:ok, String.t()} | {:error, term()}
  def canonicalize_file(path) when is_binary(path) and byte_size(path) > 0 do
    with {:ok, absolute} <- make_absolute(path),
         {:ok, canonical} <- resolve("/", split(absolute), %{}, 0),
         {:ok, %File.Stat{type: :regular}} <- File.stat(canonical) do
      {:ok, canonical}
    else
      {:ok, %File.Stat{}} -> {:error, {:not_a_regular_file, path}}
      {:error, reason} -> {:error, normalize_file_error(reason, path)}
    end
  end

  def canonicalize_file(path), do: {:error, {:invalid_attachment_path, path}}

  @spec within?(String.t(), String.t()) :: boolean()
  def within?(candidate, "/") when is_binary(candidate), do: String.starts_with?(candidate, "/")

  def within?(candidate, allowed_root)
      when is_binary(candidate) and is_binary(allowed_root) do
    candidate == allowed_root or String.starts_with?(candidate, allowed_root <> "/")
  end

  @spec overlap?(String.t(), String.t()) :: boolean()
  def overlap?(left, right), do: within?(left, right) or within?(right, left)

  defp make_absolute(path) do
    if Elixir.Path.type(path) == :absolute do
      {:ok, path}
    else
      case File.cwd() do
        {:ok, cwd} -> {:ok, cwd <> "/" <> path}
        {:error, reason} -> {:error, {:cwd_unavailable, reason}}
      end
    end
  end

  # This resolver intentionally processes `..` only after following each
  # preceding symlink. Lexically expanding the input first would authorize the
  # wrong directory for paths such as `link/../workspace`.
  #
  # `seen` is a plain map used as a set. It never leaves this module and only ever
  # answers "have I followed this link already", so a `MapSet` bought nothing here and
  # cost an opaque type that dialyzer cannot follow across the recursion.
  @spec resolve(String.t(), [String.t()], %{optional(String.t()) => true}, non_neg_integer()) ::
          {:ok, String.t()} | {:error, term()}
  defp resolve(current, [], _seen, _count), do: {:ok, current}
  defp resolve(current, ["." | rest], seen, count), do: resolve(current, rest, seen, count)

  defp resolve(current, [".." | rest], seen, count) do
    resolve(Elixir.Path.dirname(current), rest, seen, count)
  end

  defp resolve(_current, _segments, _seen, count) when count >= @max_symlinks,
    do: {:error, :too_many_symbolic_links}

  defp resolve(current, [segment | rest], seen, count) do
    candidate = Elixir.Path.join(current, segment)

    case File.lstat(candidate) do
      {:ok, %File.Stat{type: :symlink}} ->
        follow_symlink(candidate, current, rest, seen, count)

      {:ok, %File.Stat{type: :directory}} ->
        resolve(candidate, rest, seen, count)

      {:ok, %File.Stat{}} when rest == [] ->
        {:ok, candidate}

      {:ok, %File.Stat{}} ->
        {:error, {:not_a_directory, candidate}}

      {:error, reason} ->
        {:error, {:path_unavailable, candidate, reason}}
    end
  end

  @spec follow_symlink(
          String.t(),
          String.t(),
          [String.t()],
          %{optional(String.t()) => true},
          non_neg_integer()
        ) :: {:ok, String.t()} | {:error, term()}
  defp follow_symlink(candidate, current, rest, seen, count) do
    if Map.has_key?(seen, candidate) do
      {:error, {:symbolic_link_cycle, candidate}}
    else
      case File.read_link(candidate) do
        {:ok, target} ->
          next_current = if Elixir.Path.type(target) == :absolute, do: "/", else: current
          next_segments = split(target) ++ rest
          resolve(next_current, next_segments, Map.put(seen, candidate, true), count + 1)

        {:error, reason} ->
          {:error, {:symbolic_link_unreadable, candidate, reason}}
      end
    end
  end

  defp split(path), do: String.split(path, "/", trim: true)

  defp normalize_file_error({tag, _, _} = reason, _path)
       when tag in [:path_unavailable, :symbolic_link_unreadable],
       do: reason

  defp normalize_file_error(reason, _path)
       when reason in [:too_many_symbolic_links],
       do: reason

  defp normalize_file_error({:symbolic_link_cycle, _} = reason, _path), do: reason
  defp normalize_file_error({:not_a_directory, _} = reason, _path), do: reason
  defp normalize_file_error(reason, path), do: {:workspace_path_error, path, reason}
end
