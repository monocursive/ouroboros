defmodule Ouroboros.Workspace.Snapshot do
  @moduledoc """
  A pinned commit of the working tree, using a private index. Neither HEAD nor the
  developer's index is changed. Ignored files and configured provision exclusions are
  omitted; the included untracked paths are reported to the caller.
  """
  alias Ouroboros.Workspace.Git

  @max_config_bytes 64 * 1024
  @deliver_path ".ouroboros/deliver"

  def commit(workspace, task_id, opts \\ []) do
    with true <- Git.valid_id?(task_id),
         {:ok, root} <- Git.run(workspace, ["rev-parse", "--show-toplevel"], opts),
         {:ok, head} <- head(root, opts),
         {:ok, excludes} <-
           if(Keyword.get(opts, :return_snapshot, false),
             do: {:ok, [@deliver_path]},
             else: exclusions(root)
           ),
         {:ok, temporary} <- Git.temp_directory() do
      try do
        snapshot(root, head, task_id, temporary, excludes, opts)
      after
        File.rm_rf(temporary)
      end
    else
      false -> {:error, :invalid_snapshot_task_id}
      {:error, _} = error -> error
    end
  end

  def release(root, task_id, opts \\ []) do
    if Git.valid_id?(task_id),
      do: Git.run(root, ["update-ref", "-d", ref(task_id)], opts),
      else: {:error, :invalid_snapshot_task_id}
  end

  def ref(task_id), do: "refs/ouroboros/snapshots/" <> task_id

  # A return is one applicable commit containing all child edits. Its observed HEAD
  # stays separate in the snapshot so retirement still detects later commits.
  defp snapshot_parent(head, opts) do
    parent = Keyword.get(opts, :return_base, head)
    if Git.valid_commit?(parent), do: {:ok, parent}, else: {:error, :invalid_snapshot_parent}
  end

  defp head(root, opts) do
    case Git.run(root, ["rev-parse", "--verify", "HEAD^{commit}"], opts) do
      {:ok, head} -> {:ok, head}
      {:error, _} -> {:error, :snapshot_requires_a_commit}
    end
  end

  defp snapshot(root, head, task_id, temporary, excludes, opts) do
    index = Path.join(temporary, "index")
    env = [{"GIT_INDEX_FILE", index}, {"GIT_OPTIONAL_LOCKS", "0"}]
    private = Keyword.update(opts, :env, env, &(env ++ &1))
    paths = [":/"] ++ Enum.map(excludes, &(":(top,exclude)" <> &1))

    with {:ok, parent} <- snapshot_parent(head, opts),
         {:ok, original_index} <-
           Git.run(root, ["rev-parse", "--path-format=absolute", "--git-path", "index"], opts),
         :ok <- copy_index(original_index, index, root, head, private),
         {:ok, _} <- Git.run(root, ["add", "-A", "--" | paths], private),
         # Remove excluded tracked paths from the private index too. Merely excluding
         # them from `add` would ship the version staged in the real index.
         {:ok, _} <-
           Git.run(
             root,
             [
               "rm",
               "-r",
               "-f",
               "--cached",
               "--ignore-unmatch",
               "--" | Enum.map(excludes, &(":(top)" <> &1))
             ],
             private
           ),
         {:ok, untracked} <-
           Git.run(root, ["ls-files", "--others", "--exclude-standard", "-z", "--" | paths], opts),
         {:ok, tree} <- Git.run(root, ["write-tree"], private),
         {:ok, commit} <-
           Git.run(
             root,
             [
               "-c",
               "user.name=Ouroboros",
               "-c",
               "user.email=agent@ouroboros.local",
               "commit-tree",
               tree,
               "-p",
               parent,
               "-m",
               "Ouroboros snapshot #{task_id}"
             ],
             private
           ),
         {:ok, roots} <- Git.run(root, ["rev-list", "--max-parents=0", head], opts),
         {:ok, sizes} <- Git.run(root, ["ls-tree", "-r", "--format=%(objectsize)", tree], opts),
         {:ok, _} <- Git.run(root, ["update-ref", ref(task_id), commit], opts) do
      included = String.split(untracked, <<0>>, trim: true)

      repo_id =
        :crypto.hash(
          :sha256,
          roots |> String.split("\n", trim: true) |> Enum.sort() |> Enum.join("\n")
        )
        |> Base.encode16(case: :lower)

      {:ok,
       %{
         root: root,
         head: head,
         commit: commit,
         tree: tree,
         repo_id: repo_id,
         task_id: task_id,
         untracked: Enum.take(included, 200),
         untracked_count: length(included),
         byte_estimate:
           sizes
           |> String.split("\n", trim: true)
           |> Enum.reduce(0, fn size, sum ->
             case Integer.parse(size) do
               {n, ""} -> sum + n
               _ -> sum
             end
           end),
         created_at: DateTime.utc_now() |> DateTime.to_iso8601(),
         name: Path.basename(root)
       }}
    end
  end

  defp copy_index(source, target, root, head, opts) do
    case File.cp(source, target) do
      :ok ->
        :ok

      {:error, :enoent} ->
        case Git.run(root, ["read-tree", head], opts) do
          {:ok, _} -> :ok
          error -> error
        end

      error ->
        error
    end
  end

  defp exclusions(root) do
    path = Path.join(root, "ouroboros.toml")

    case File.lstat(path) do
      {:error, :enoent} ->
        {:ok, [@deliver_path]}

      {:ok, %{type: :regular, size: size}} when size <= @max_config_bytes ->
        with {:ok, text} <- File.read(path),
             true <- byte_size(text) <= @max_config_bytes,
             {:ok, config} <- Toml.decode(text),
             provision when is_map(provision) <- Map.get(config, "provision", %{}),
             excludes when is_list(excludes) and length(excludes) <= 64 <-
               Map.get(provision, "exclude", []),
             true <- Enum.all?(excludes, &valid_exclude?/1) do
          {:ok, Enum.uniq([@deliver_path | excludes])}
        else
          _ -> {:error, :invalid_provision_excludes}
        end

      _ ->
        {:error, :invalid_provision_config}
    end
  end

  defp valid_exclude?(path) do
    is_binary(path) and byte_size(path) in 1..1024 and not String.starts_with?(path, ["/", ":"]) and
      not String.contains?(path, [<<0>>, "\n"]) and ".." not in Path.split(path)
  end
end
