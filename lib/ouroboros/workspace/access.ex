defmodule Ouroboros.Workspace.Access do
  @moduledoc """
  Narrow write grants derived from this node's durable provisioned-worktree registry.
  A session's supplied metadata is never authority for a path outside its workspace.
  """
  alias Ouroboros.Workspace.{Path, Worktree}
  alias Ouroboros.Provider.Native.Paths

  @names [".git", ".ouroboros"]

  def recorded_git_dir(root, repository) do
    with {:ok, text} <- small_file(Elixir.Path.join(root, ".git")),
         "gitdir: " <> value <- String.trim(text),
         {:ok, dir} <- Path.canonicalize(value),
         true <- Path.within?(dir, Elixir.Path.join(repository, "worktrees")) do
      dir
    else
      _ -> nil
    end
  end

  def grants(root) when is_binary(root) do
    with {:ok, root} <- Path.canonicalize(root),
         %{provisioned: true, node: owner, repo_id: id, repository: repository, git_dir: git_dir} <-
           Worktree.find(root),
         true <- owner == Atom.to_string(node()),
         true <- is_binary(id) and Regex.match?(~r/\A[0-9a-f]{64}\z/, id),
         data when is_binary(data) <- Application.get_env(:ouroboros, :data_dir),
         {:ok, expected} <- Path.canonicalize(Elixir.Path.join([data, "mirrors", id])),
         true <- repository == expected,
         true <- is_binary(git_dir),
         {:ok, ^git_dir} <- Path.canonicalize(git_dir),
         true <- Path.within?(git_dir, Elixir.Path.join(repository, "worktrees")),
         true <- recorded_git_dir(root, repository) == git_dir,
         {:ok, backlink} <- small_file(Elixir.Path.join(git_dir, "gitdir")),
         true <- String.trim(backlink) == Elixir.Path.join(root, ".git"),
         {:ok, common} <- small_file(Elixir.Path.join(git_dir, "commondir")),
         {:ok, ^repository} <- Path.canonicalize(Elixir.Path.join(git_dir, String.trim(common))),
         delivery = Elixir.Path.join(root, ".ouroboros/deliver"),
         {:ok, ^delivery} <- Path.canonicalize(delivery),
         objects = Elixir.Path.join(repository, "objects"),
         {:ok, ^objects} <- Path.canonicalize(objects) do
      %{delivery: delivery, git: [git_dir, objects]}
    else
      _ -> nil
    end
  end

  def grants(_), do: nil

  def policy(policy, root) do
    policy = if provisioned?(root), do: Map.put(policy, :protected_segments, @names), else: policy

    case grants(root) do
      %{delivery: delivery, git: git}
      when policy.mode in [:workspace_write, :workspace_write_escalated] ->
        exceptions =
          [delivery] ++ if(policy.mode == :workspace_write_escalated, do: git, else: [])

        policy |> Map.put(:write_exceptions, exceptions) |> Map.put(:protected_segments, @names)

      _ ->
        policy
    end
  end

  defp provisioned?(root) when is_binary(root) do
    with {:ok, canonical} <- Path.canonicalize(root),
         %{provisioned: true, node: owner} <- Worktree.find(canonical) do
      owner == Atom.to_string(node())
    else
      _ -> false
    end
  end

  defp provisioned?(_), do: false

  def escalation_text(text, policy) when is_binary(text) do
    Enum.reduce(policy.writable, text, fn root, evidence ->
      case grants(root) do
        %{git: paths} ->
          Enum.reduce(paths, evidence, fn path, acc ->
            Regex.replace(
              Regex.compile!(Regex.escape(path) <> "(?=/|$|['\"\\s:])"),
              acc,
              "<worktree-git>"
            )
          end)

        _ ->
          evidence
      end
    end)
  end

  def escalation_text(text, _policy), do: text

  def delivery_write?(path) when is_binary(path) do
    # Find the enclosing root from the exact reserved delivery suffix. This avoids a
    # registry scan for every ordinary write and still validates the record below.
    case String.split(path, "/.ouroboros/deliver", parts: 2) do
      [root, suffix] ->
        with true <- suffix == "" or String.starts_with?(suffix, "/"),
             %{delivery: delivery} <- grants(root),
             false <-
               Enum.any?(
                 @names,
                 &Ouroboros.Control.Permissions.Paths.has_segment?(suffix, &1, case: :insensitive)
               ),
             {:ok, canonical} <- Paths.resolve(path, %{root: root, roots: [root]}),
             true <- canonical == path and Path.within?(canonical, delivery) do
          true
        else
          _ -> false
        end

      _ ->
        false
    end
  end

  def delivery_write?(_), do: false

  defp small_file(path) do
    with {:ok, %{type: :regular, size: size}} <- File.lstat(path),
         true <- size <= 4096,
         {:ok, text} <- File.read(path) do
      {:ok, text}
    else
      _ -> {:error, :invalid_git_metadata}
    end
  end
end
