defmodule Ouroboros.Workspace.Mirrors do
  @moduledoc """
  Node-owned bare mirrors. Callers name repository identities and commits, never paths.
  Imports are serialized per mirror, size/digest checked before Git sees a bundle, and
  interrupted uploads are removed at boot. Imported work is kept until acknowledged.
  """
  use GenServer
  alias Ouroboros.Workspace.{Bundle, Git, Worktree}
  alias Ouroboros.Workspace.Path, as: WorkspacePath
  @max_mirrors 64
  @max_worktrees 16

  def start_link(opts \\ []),
    do: GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))

  def heads(repo_id, opts \\ []), do: call({:heads, repo_id}, opts)

  def begin_import(repo_id, metadata, source_node, opts \\ []),
    do: call({:begin, repo_id, metadata, source_node}, opts)

  def put_chunk(token, offset, data, opts \\ []), do: call({:chunk, token, offset, data}, opts)
  def finish_import(token, commit, opts \\ []), do: call({:finish, token, commit}, opts, 260_000)
  def cancel_import(token, opts \\ []), do: call({:cancel, token}, opts)

  def worktree(repo_id, commit, task_id, opts \\ []),
    do:
      call({:worktree, repo_id, commit, task_id, Keyword.get(opts, :source_node)}, opts, 130_000)

  defp call(message, opts, timeout \\ 30_000),
    do: GenServer.call(Keyword.get(opts, :server, __MODULE__), message, timeout)

  @impl true
  def init(opts) do
    data = Keyword.get(opts, :data_dir, Application.get_env(:ouroboros, :data_dir))
    root = if is_binary(data) and data != "", do: Path.join(data, "mirrors")
    if root, do: Bundle.reconcile(root)
    Process.send_after(self(), :expire, 30_000)
    {:ok, %{root: root, transfers: %{}, worktree_opts: Keyword.get(opts, :worktree_opts, [])}}
  end

  @impl true
  def handle_call({:heads, repo_id}, _from, state) do
    result = with {:ok, path} <- mirror(state, repo_id), do: read_heads(path)
    {:reply, result, state}
  end

  def handle_call({:begin, repo_id, metadata, source}, _from, state) do
    result =
      with {:ok, path} <- mirror(state, repo_id),
           false <- Enum.any?(state.transfers, fn {_id, t} -> t.repo_id == repo_id end),
           true <- map_size(state.transfers) < @max_mirrors,
           true <- is_atom(source),
           {:ok, transfer} <- Bundle.begin(state.root, metadata) do
        {:ok, Map.merge(transfer, %{repo_id: repo_id, repository: path, source: source})}
      else
        true -> {:error, :mirror_import_busy}
        false -> {:error, :import_capacity_exceeded}
        error -> error
      end

    case result do
      {:ok, transfer} ->
        {:reply, {:ok, transfer.token}, put_in(state.transfers[transfer.token], transfer)}

      error ->
        {:reply, error, state}
    end
  end

  def handle_call({:chunk, token, offset, data}, _from, state) do
    case Map.fetch(state.transfers, token) do
      {:ok, transfer} ->
        case Bundle.append(transfer, offset, data) do
          {:ok, updated} -> {:reply, :ok, put_in(state.transfers[token], updated)}
          error -> {:reply, error, state}
        end

      :error ->
        {:reply, {:error, :unknown_import}, state}
    end
  end

  def handle_call({:finish, token, commit}, _from, state) do
    case Map.pop(state.transfers, token) do
      {nil, _} ->
        {:reply, {:error, :unknown_import}, state}

      {transfer, transfers} ->
        result =
          with true <- commit == transfer.metadata.commit,
               :ok <- Bundle.verify(transfer),
               {:ok, _} <- Git.run(transfer.repository, ["bundle", "verify", transfer.path]),
               {:ok, _} <-
                 Git.run(transfer.repository, [
                   "-c",
                   "core.hooksPath=/dev/null",
                   "fetch",
                   "--no-write-fetch-head",
                   transfer.path,
                   "#{commit}:refs/ouroboros/incoming/#{transfer.metadata.task_id}"
                 ]) do
            {:ok, %{repo_id: transfer.repo_id, commit: commit, bytes: transfer.bytes}}
          else
            false -> {:error, :unexpected_import_commit}
            error -> error
          end

        Bundle.discard(transfer)
        {:reply, result, %{state | transfers: transfers}}
    end
  end

  def handle_call({:cancel, token}, _from, state) do
    {transfer, transfers} = Map.pop(state.transfers, token)
    if transfer, do: Bundle.discard(transfer)
    {:reply, :ok, %{state | transfers: transfers}}
  end

  def handle_call({:worktree, repo_id, commit, task_id, source_node}, _from, state) do
    result =
      with true <- Git.valid_id?(task_id) and Git.valid_commit?(commit),
           true <- Worktree.admissible?(state.worktree_opts),
           {:ok, repository} <- mirror(state, repo_id),
           {:ok, ^commit} <-
             Git.run(repository, [
               "rev-parse",
               "--verify",
               "refs/ouroboros/incoming/#{task_id}^{commit}"
             ]),
           true <-
             Enum.count(Worktree.list(state.worktree_opts), &(&1.repository == repository)) <
               @max_worktrees do
        Worktree.create_detached(
          repository,
          commit,
          task_id,
          Keyword.merge(state.worktree_opts,
            provisioned: true,
            repo_id: repo_id,
            source_node: source_node
          )
        )
      else
        false -> {:error, :provisioned_worktree_not_admitted_or_at_capacity}
        {:ok, _other} -> {:error, :unexpected_import_commit}
        error -> error
      end

    {:reply, result, state}
  end

  @impl true
  def handle_info(:expire, state) do
    {expired, live} =
      Enum.split_with(state.transfers, fn {_id, transfer} -> Bundle.expired?(transfer) end)

    Enum.each(expired, fn {_id, transfer} -> Bundle.discard(transfer) end)
    Process.send_after(self(), :expire, 30_000)
    {:noreply, %{state | transfers: Map.new(live)}}
  end

  defp mirror(%{root: nil}, _id), do: {:error, :provision_requires_data_directory}

  defp mirror(state, id) do
    if is_binary(id) and Regex.match?(~r/\A[a-f0-9]{64}\z/, id) do
      path = Path.join(state.root, id)

      with :ok <- File.mkdir_p(state.root),
           :ok <- ensure_mirror(path, state.root),
           {:ok, canonical} <- WorkspacePath.canonicalize(path),
           {:ok, root} <- WorkspacePath.canonicalize(state.root),
           true <- WorkspacePath.within?(canonical, root) do
        {:ok, canonical}
      else
        false -> {:error, :mirror_path_escapes}
        error -> error
      end
    else
      {:error, :invalid_repository_id}
    end
  end

  defp ensure_mirror(path, root) do
    case File.lstat(path) do
      {:ok, %{type: :directory}} ->
        :ok

      {:error, :enoent} ->
        with {:ok, entries} <- File.ls(root),
             true <- Enum.count(entries, &(byte_size(&1) == 64)) < @max_mirrors,
             {:ok, _} <- Git.run(root, ["init", "--bare", "--template=", path]),
             :ok <- File.chmod(path, 0o700) do
          :ok
        else
          false -> {:error, :mirror_capacity_exceeded}
          error -> error
        end

      _ ->
        {:error, :invalid_mirror_directory}
    end
  end

  defp read_heads(path) do
    case Git.run(path, [
           "for-each-ref",
           "--count=64",
           "--sort=-creatordate",
           "--format=%(objectname)",
           "refs/ouroboros/incoming/"
         ]) do
      {:ok, text} -> {:ok, String.split(text, "\n", trim: true)}
      error -> error
    end
  end
end
