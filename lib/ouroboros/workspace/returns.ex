defmodule Ouroboros.Workspace.Returns do
  @moduledoc """
  Parent-owned return capabilities. Repository paths are registered locally and never
  accepted from a remote child. Chunk uploads are bounded and serialized per repository;
  a receipt is issued only after Git objects and deliveries have reached their destinations.
  """
  use GenServer
  alias Ouroboros.Workspace.{Bundle, Deliveries, Git, Snapshot}
  @max_tasks 500

  def start_link(opts \\ []),
    do: GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))

  def register(snapshot, opts \\ []), do: call({:register, snapshot}, opts)

  def begin_import(capability, kind, metadata, opts \\ []),
    do: call({:begin, capability, kind, metadata}, opts)

  def put_chunk(token, offset, data, opts \\ []), do: call({:chunk, token, offset, data}, opts)

  def finish_import(token, commit, opts \\ []),
    do: call({:finish_import, token, commit}, opts, 260_000)

  def cancel_import(token, opts \\ []), do: call({:cancel, token}, opts)

  def acknowledge(capability, commit, files, opts \\ []),
    do: call({:acknowledge, capability, commit, files}, opts, 260_000)

  def unregister(capability, opts \\ []), do: call({:unregister, capability}, opts)
  def ref(task_id), do: "refs/ouroboros/subagents/" <> task_id

  defp call(message, opts, timeout \\ 30_000),
    do: GenServer.call(Keyword.get(opts, :server, __MODULE__), message, timeout)

  @impl true
  def init(opts) do
    data = Keyword.get(opts, :data_dir)
    if data, do: Bundle.reconcile(Path.join(data, "returns"))
    Process.send_after(self(), :expire, 30_000)
    {:ok, %{data: data, capabilities: %{}, transfers: %{}}}
  end

  @impl true
  def handle_call({:register, snapshot}, _from, state) do
    data = state.data || Application.get_env(:ouroboros, :data_dir)
    # Keep receipts for retry, but never let completed tasks prevent new work forever.
    # Unacknowledged tasks retain their capabilities and their pinned source snapshot.
    state = make_registration_room(state)

    result =
      with true <- map_size(state.capabilities) < @max_tasks,
           true <-
             is_binary(data) and data != "" and Git.valid_id?(snapshot.task_id) and
               Git.valid_commit?(snapshot.commit),
           {:ok, root} <- Git.run(snapshot.root, ["rev-parse", "--show-toplevel"]),
           true <- root == snapshot.root,
           :ok <- File.mkdir_p(Path.join(data, "returns")) do
        token = Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)

        {:ok, token,
         %{
           snapshot: snapshot,
           root: root,
           data: data,
           result: nil,
           bundle_commit: nil,
           archive: nil
         }}
      else
        false -> {:error, :return_registration_unavailable_or_at_capacity}
        error -> error
      end

    case result do
      {:ok, token, entry} -> {:reply, {:ok, token}, put_in(state.capabilities[token], entry)}
      error -> {:reply, error, state}
    end
  end

  def handle_call({:begin, capability, kind, metadata}, _from, state) do
    result =
      with {:ok, entry} <- fetch(state, capability),
           true <- is_nil(entry.result),
           true <-
             is_map(metadata) and kind in [:bundle, :deliveries] and
               Map.get(metadata, :task_id) == entry.snapshot.task_id,
           true <-
             kind != :deliveries or
               (is_integer(Map.get(metadata, :bytes)) and metadata.bytes <= Deliveries.max_bytes()),
           false <-
             Enum.any?(state.transfers, fn {_token, transfer} -> transfer.root == entry.root end),
           true <- map_size(state.transfers) < 64,
           {:ok, transfer} <- Bundle.begin(Path.join(entry.data, "returns"), metadata) do
        {:ok, Map.merge(transfer, %{capability: capability, root: entry.root, kind: kind})}
      else
        false -> {:error, :invalid_return_import}
        true -> {:error, :return_repository_busy}
        error -> error
      end

    case result do
      {:ok, transfer} ->
        {:reply, {:ok, transfer.token}, put_in(state.transfers[transfer.token], transfer)}

      error ->
        {:reply, error, state}
    end
  end

  def handle_call({:chunk, token, offset, bytes}, _from, state) do
    case Map.fetch(state.transfers, token) do
      {:ok, transfer} ->
        case Bundle.append(transfer, offset, bytes) do
          {:ok, updated} -> {:reply, :ok, put_in(state.transfers[token], updated)}
          error -> {:reply, error, state}
        end

      :error ->
        {:reply, {:error, :unknown_return_import}, state}
    end
  end

  def handle_call({:finish_import, token, commit}, _from, state) do
    case Map.pop(state.transfers, token) do
      {nil, _} ->
        {:reply, {:error, :unknown_return_import}, state}

      {transfer, transfers} ->
        state = %{state | transfers: transfers}

        result =
          with {:ok, entry} <- fetch(state, transfer.capability),
               true <- commit == transfer.metadata.commit,
               :ok <- Bundle.verify(transfer) do
            install(transfer, entry)
          else
            false -> {:error, :unexpected_return_commit}
            error -> error
          end

        case result do
          {:ok, entry} ->
            if transfer.kind == :bundle, do: Bundle.discard(transfer)

            {:reply, {:ok, %{commit: commit}},
             put_in(state.capabilities[transfer.capability], entry)}

          error ->
            Bundle.discard(transfer)
            {:reply, error, state}
        end
    end
  end

  def handle_call({:acknowledge, capability, commit, files}, _from, state) do
    case fetch(state, capability) do
      {:ok, %{result: result}} when is_map(result) ->
        if result.returned_commit == commit and result.manifest == files,
          do: {:reply, {:ok, result}, state},
          else: {:reply, {:error, :return_already_acknowledged}, state}

      {:ok, entry} ->
        result =
          with true <- Git.valid_commit?(commit) and entry.bundle_commit == commit,
               true <- Deliveries.valid_manifest?(files),
               {:ok, delivered} <- receive_deliveries(entry, files),
               {:ok, changed} <-
                 Git.run(entry.root, [
                   "diff",
                   "--name-status",
                   "--no-renames",
                   "-z",
                   entry.snapshot.commit,
                   commit
                 ]),
               {:ok, _} <- Snapshot.release(entry.root, entry.snapshot.task_id) do
            {:ok,
             %{
               returned_ref: ref(entry.snapshot.task_id),
               returned_commit: commit,
               returned_files: changed_files(changed),
               deliveries: delivered,
               manifest: files,
               acknowledged: true,
               task_id: entry.snapshot.task_id
             }}
          else
            false -> {:error, :return_not_verified}
            error -> error
          end

        case result do
          {:ok, receipt} ->
            if entry.archive, do: Bundle.discard(entry.archive)

            {:reply, {:ok, receipt},
             put_in(state.capabilities[capability], %{entry | result: receipt, archive: nil})}

          error ->
            {:reply, error, state}
        end

      error ->
        {:reply, error, state}
    end
  end

  def handle_call({:cancel, token}, _from, state) do
    {transfer, rest} = Map.pop(state.transfers, token)
    if transfer, do: Bundle.discard(transfer)
    {:reply, :ok, %{state | transfers: rest}}
  end

  def handle_call({:unregister, token}, _from, state) do
    {entry, rest} = Map.pop(state.capabilities, token)

    if entry do
      if entry.archive, do: Bundle.discard(entry.archive)
      Snapshot.release(entry.root, entry.snapshot.task_id)
    end

    {:reply, :ok, %{state | capabilities: rest}}
  end

  @impl true
  def handle_info(:expire, state) do
    {expired, live} =
      Enum.split_with(state.transfers, fn {_id, transfer} -> Bundle.expired?(transfer) end)

    Enum.each(expired, fn {_id, transfer} -> Bundle.discard(transfer) end)
    Process.send_after(self(), :expire, 30_000)
    {:noreply, %{state | transfers: Map.new(live)}}
  end

  defp make_registration_room(state) when map_size(state.capabilities) < @max_tasks, do: state

  defp make_registration_room(state) do
    case Enum.find(state.capabilities, fn {_token, entry} -> is_map(entry.result) end) do
      {token, _entry} -> %{state | capabilities: Map.delete(state.capabilities, token)}
      nil -> state
    end
  end

  defp fetch(state, capability) do
    case Map.fetch(state.capabilities, capability) do
      {:ok, entry} -> {:ok, entry}
      :error -> {:error, :unknown_return_capability}
    end
  end

  defp install(%{kind: :deliveries} = transfer, entry) do
    if entry.archive, do: Bundle.discard(entry.archive)
    {:ok, %{entry | archive: transfer}}
  end

  defp install(transfer, entry) do
    temporary_ref = "refs/ouroboros/returning/" <> transfer.token
    commit = transfer.metadata.commit

    result =
      with {:ok, _} <- Git.run(entry.root, ["bundle", "verify", transfer.path]),
           {:ok, _} <-
             Git.run(entry.root, [
               "-c",
               "core.hooksPath=/dev/null",
               "fetch",
               "--no-write-fetch-head",
               transfer.path,
               "#{commit}:#{temporary_ref}"
             ]),
           {:ok, _} <-
             Git.run(entry.root, ["merge-base", "--is-ancestor", entry.snapshot.commit, commit]),
           {:ok, _} <- Git.run(entry.root, ["update-ref", ref(entry.snapshot.task_id), commit]) do
        {:ok, %{entry | bundle_commit: commit}}
      end

    Git.run(entry.root, ["update-ref", "-d", temporary_ref])
    result
  end

  defp receive_deliveries(%{archive: nil}, []), do: {:ok, []}
  defp receive_deliveries(%{archive: nil}, _), do: {:error, :deliveries_not_received}

  defp receive_deliveries(entry, files) do
    directory = Path.join(entry.data, "deliveries")
    target = Path.join(directory, entry.snapshot.task_id)
    temporary = target <> ".incoming-" <> entry.archive.token

    with :ok <- File.mkdir_p(directory),
         {:ok, verified} <- Deliveries.extract(entry.archive.path, temporary, files),
         :ok <- File.rename(temporary, target) do
      {:ok,
       Enum.map(verified, fn file -> %{path: Path.join(target, file.path), bytes: file.bytes} end)}
    else
      error ->
        File.rm_rf(temporary)
        error
    end
  end

  defp changed_files(text) do
    text
    |> String.split(<<0>>, trim: true)
    |> Enum.chunk_every(2)
    |> Enum.take(16)
    |> Enum.flat_map(fn
      [status, path] -> [%{status: status, path: path}]
      _ -> []
    end)
  end
end
