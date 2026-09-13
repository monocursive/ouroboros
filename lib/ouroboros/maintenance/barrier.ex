defmodule Ouroboros.Maintenance.Barrier do
  @moduledoc """
  Target-owned authoritative read-only inventory barrier.

  The barrier accepts only a locally idle target: no live interactive coordinator, no
  nonterminal session, no queued/active turn, no pending Epoch write, and an exact match
  between Store workspace lease IDs and Workspace.Manager claims. It then delegates the
  immutable bounded value and paging contract to `Maintenance.Inventory`.

  This is cooperative same-UID target evidence. It does not stop processes, authenticate
  the external controller, or attest an OS process.
  """

  alias Ouroboros.Interactive.{State, Store, Task}
  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Maintenance.{Epoch, Inventory, NativeInventory}
  alias Ouroboros.Workspace

  @spec freeze(non_neg_integer(), keyword()) :: {:ok, map()} | {:error, term()}
  def freeze(generation, opts \\ [])

  def freeze(generation, opts) when is_integer(generation) and generation >= 0 do
    epoch_server = Keyword.get(opts, :epoch, Epoch)
    store_server = Keyword.get(opts, :store, Store)
    workspace_server = Keyword.get(opts, :workspace, Ouroboros.Workspace.Manager)
    ledger_server = Keyword.get(opts, :ledger, EffectLedger)
    native_source = Keyword.get(opts, :native_inventory, {NativeInventory, :snapshot})

    with %{pending: []} = epoch <- Epoch.observe(epoch_server),
         sessions when is_list(sessions) <- Store.list(store_server),
         leases when is_list(leases) <- Workspace.list(server: workspace_server),
         {:ok, effects} <-
           EffectLedger.list([limit: EffectLedger.query_limits().max], ledger_server),
         :ok <- settled_effects(effects),
         :ok <- no_live_coordinators(sessions),
         {:ok, native} <- native_snapshot(native_source, generation, opts),
         :ok <- native_idle(native),
         {:ok, rows, reservations} <- rows(sessions, leases, native.rows),
         root_digest <- digest({epoch.epoch, sessions, leases, effects, native.root_digest}),
         {:ok, snapshot} <-
           Inventory.freeze(rows,
             local_node: Atom.to_string(node()),
             generation: generation,
             root_digest: root_digest,
             reservations: reservations
           ) do
      {:ok,
       %{
         snapshot: snapshot,
         write_epoch: epoch.epoch,
         native_release: native[:release],
         native_rows: native.rows
       }}
    else
      %{pending: [_ | _]} -> {:error, :pending_epoch_write}
      {:error, reason} -> {:error, reason}
      _ -> {:error, :barrier_authority_unavailable}
    end
  catch
    :exit, _reason -> {:error, :barrier_authority_unavailable}
  end

  def freeze(_generation, _opts), do: {:error, :invalid_generation}

  @spec release(map() | nil) :: :ok | {:error, term()}
  def release(nil), do: :ok
  def release(release), do: NativeInventory.release(release)

  @spec revalidate(map()) :: :ok | {:error, term()}
  def revalidate(%{native_release: nil}), do: :ok

  def revalidate(%{native_release: release, native_rows: rows}),
    do: NativeInventory.revalidate(release, rows)

  # Custom barrier callbacks are an isolated test/embedding compatibility seam. The
  # production Barrier always returns both Native fields.
  def revalidate(%{snapshot: _snapshot}), do: :ok
  def revalidate(_barrier), do: {:error, :native_revalidation_unavailable}

  defp no_live_coordinators(sessions) do
    case Enum.find(sessions, &is_pid(Task.whereis(&1.id))) do
      nil -> :ok
      session -> {:error, {:live_coordinator, session.id}}
    end
  end

  defp settled_effects(effects) do
    case Enum.find(effects, &(&1.status in [:started, :ambiguous])) do
      nil -> :ok
      effect -> {:error, {:unsettled_effect, effect.id, effect.status}}
    end
  end

  defp rows(sessions, leases, native_rows) do
    by_id = Map.new(leases, &{&1.id, &1})
    native_by_logical = Map.new(native_rows, &{&1.logical_id, &1})

    store_ids = MapSet.new(sessions, & &1.id)

    case Enum.find(native_rows, &(not MapSet.member?(store_ids, &1.logical_id))) do
      nil -> build_rows(sessions, by_id, native_by_logical)
      extra -> {:error, {:native_participant_without_store, extra.logical_id}}
    end
  end

  defp build_rows(sessions, by_id, native_by_logical) do
    Enum.reduce_while(sessions, {:ok, [], %{}}, fn session, {:ok, rows, reservations} ->
      with true <- State.terminal?(session) || {:error, {:nonterminal_session, session.id}},
           true <- idle_turns?(session) || {:error, {:nonidle_turn, session.id}},
           {:ok, reservation} <- reservation(session, by_id),
           {:ok, native} <- native_for(session, native_by_logical) do
        lineage =
          [Map.get(session, :forked_from), Map.get(session, :handed_off_from)]
          |> Enum.reject(&is_nil/1)
          |> Enum.map(&%{session_id: &1, node: Atom.to_string(session.node)})

        bytes = :erlang.term_to_binary({State.durable_term(session), native}, [:deterministic])

        row = %{
          session_id: session.id,
          generation: generation(session.runtime_generation),
          checkpoint_sha256: sha(bytes),
          checkpoint_length: byte_size(bytes),
          owner_node: Atom.to_string(session.node),
          process_generation: max(1, generation(session.runtime_generation)),
          lifecycle: :idle,
          active_count: 0,
          queued_count: 0,
          workspace_reservation: reservation,
          handoff_lineage: lineage
        }

        {:cont, {:ok, [row | rows], Map.put(reservations, session.id, reservation)}}
      else
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp native_for(%{provider_session_id: nil}, _native), do: {:ok, nil}

  defp native_for(session, native) do
    case Map.get(native, session.id) do
      %{provider_session_id: id} = row when id == session.provider_session_id -> {:ok, row}
      nil -> {:error, {:native_participant_missing, session.id}}
      _ -> {:error, {:native_identity_mismatch, session.id}}
    end
  end

  defp native_snapshot({module, function}, generation, opts),
    do: apply(module, function, [generation, opts])

  defp native_snapshot(fun, generation, opts) when is_function(fun, 2), do: fun.(generation, opts)
  defp native_snapshot(_, _, _), do: {:error, :invalid_native_inventory}

  defp native_idle(%{rows: rows, root_digest: root}) when is_list(rows) and is_binary(root) do
    case Enum.find(
           rows,
           &(&1.active_count != 0 or &1.queued_count != 0 or &1.unresolved_count != 0)
         ) do
      nil ->
        :ok

      row ->
        {:error,
         {:native_activity, row.logical_id, row.active_count, row.queued_count,
          row.unresolved_count}}
    end
  end

  defp native_idle(_), do: {:error, :invalid_native_inventory}

  defp reservation(%{workspace_lease_id: nil}, _by_id), do: {:ok, nil}

  defp reservation(session, by_id) do
    case Map.get(by_id, session.workspace_lease_id) do
      %{root: root, task_id: "interactive:" <> id} when id == session.id ->
        {:ok,
         %{session_id: session.id, generation: generation(session.runtime_generation), root: root}}

      _ ->
        {:error, {:workspace_reservation_mismatch, session.id}}
    end
  end

  defp idle_turns?(session) do
    Enum.all?(session.turns, fn {_id, turn} -> State.terminal_turn?(turn) end)
  end

  defp generation(value) when is_binary(value), do: :erlang.phash2(value, 2_147_483_647) + 1
  defp generation(_), do: 0
  defp sha(bytes), do: :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)
  defp digest(term), do: term |> :erlang.term_to_binary([:deterministic]) |> sha()
end
