defmodule Ouroboros.Storage.ETSTest do
  use ExUnit.Case, async: true
  alias Ouroboros.Storage.ETS

  setup do
    name = :"storage_owner_#{System.unique_integer([:positive])}"
    pid = start_supervised!({ETS, name: name})
    %{owner: name, pid: pid, opts: [owner: name, table: :checkpoints]}
  end

  test "checkpoint contract isolates namespaces, replaces and deletes", %{opts: opts} do
    assert :not_found = ETS.get_checkpoint({:key, 1}, opts)
    assert :ok = ETS.put_checkpoint({:key, 1}, %{old: true}, opts)
    assert :ok = ETS.put_checkpoint({:key, 1}, %{new: true}, opts)
    assert {:ok, %{new: true}} = ETS.get_checkpoint({:key, 1}, opts)
    assert :not_found = ETS.get_checkpoint({:key, 1}, Keyword.put(opts, :table, :other))
    assert :ok = ETS.delete_checkpoint({:key, 1}, opts)
    assert :ok = ETS.delete_checkpoint({:key, 1}, opts)
    assert :not_found = ETS.get_checkpoint({:key, 1}, opts)
  end

  test "first caller death does not own or erase the table", %{opts: opts, pid: owner} do
    task = Task.async(fn -> ETS.put_checkpoint(:key, :retained, opts) end)
    assert :ok = Task.await(task)
    assert {:ok, :retained} = ETS.get_checkpoint(:key, opts)
    %{checkpoints: table} = :sys.get_state(owner)
    assert :ets.info(table, :owner) == owner
    assert :ets.info(table, :named_table) == false
  end

  test "owner lifecycle reclaims its tables and never falls back to caller ownership", %{
    opts: opts,
    pid: owner
  } do
    assert :ok = ETS.put_checkpoint(:key, :value, opts)
    %{checkpoints: table} = :sys.get_state(owner)
    assert :ok = stop_supervised(ETS)
    assert :ets.info(table) == :undefined
    assert {:error, :storage_owner_unavailable} = ETS.get_checkpoint(:key, opts)
    assert {:error, :storage_owner_unavailable} = ETS.put_checkpoint(:key, :value, opts)
  end

  test "invalid options and storage configuration are explicit", %{owner: owner} do
    assert {:error, :invalid_storage_options} =
             ETS.get_checkpoint(:key, table: "remote-name", owner: owner)

    assert {:error, :invalid_storage_options} = ETS.get_checkpoint(:key, %{})
    assert {ETS, []} = Ouroboros.Storage.normalize_storage(ETS)

    assert {ETS, [table: :some_table]} =
             Ouroboros.Storage.normalize_storage({ETS, table: :some_table})

    for invalid <- [nil, false, "adapter", {ETS, [:invalid]}, {ETS, %{table: :value}}] do
      assert_raise ArgumentError, fn -> Ouroboros.Storage.normalize_storage(invalid) end
    end
  end
end
