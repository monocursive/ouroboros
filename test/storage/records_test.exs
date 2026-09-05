defmodule Ouroboros.Storage.RecordsTest do
  use ExUnit.Case, async: true
  alias Ouroboros.Storage.Records

  defmodule Adapter do
    def get_checkpoint(key, opts) do
      Agent.get(opts[:pid], &Map.get(&1.disk, key, :not_found))
    end

    def put_checkpoint(key, value, opts) do
      Agent.get_and_update(opts[:pid], fn state ->
        result = if state.fail == key, do: state.error, else: :ok

        disk =
          if result == :ok or match?({:error, {:commit_outcome_unknown, _}}, result),
            do: Map.put(state.disk, key, {:ok, value}),
            else: state.disk

        {result, %{state | disk: disk, writes: [{key, value} | state.writes]}}
      end)
    end

    def delete_checkpoint(key, opts),
      do: Agent.update(opts[:pid], &%{&1 | disk: Map.delete(&1.disk, key)})
  end

  setup do
    pid =
      start_supervised!(
        {Agent, fn -> %{disk: %{}, writes: [], fail: nil, error: {:error, :disk_full}} end}
      )

    repo =
      Records.new(Adapter, [pid: pid], :tasks, %{
        invalid: :invalid,
        unreadable: :unreadable,
        migration: :migration,
        quarantine: :quarantine
      })

    %{repo: repo, pid: pid}
  end

  defp decode(id, %{id: id} = record), do: {:ok, record}
  defp decode(_, _), do: :error

  test "an update writes only its record, independent of other histories", %{repo: repo, pid: pid} do
    a = %{id: "a", events: ["before"]}
    b = %{id: "b", events: [String.duplicate("b", 100_000)]}
    assert :ok = Records.put(repo, %{}, "a", a)
    assert :ok = Records.put(repo, %{"a" => a}, "b", b)
    Agent.update(pid, &%{&1 | writes: []})
    updated = %{a | events: ["after"]}
    assert :ok = Records.put(repo, %{"a" => a, "b" => b}, "a", updated)
    assert [{key, %{"a" => ^updated}}] = Agent.get(pid, & &1.writes)
    assert key == Records.record_key(repo, "a")
    assert {:ok, %{"a" => ^updated, "b" => ^b}} = Records.load(repo, &decode/2)
  end

  test "migration keeps the aggregate authoritative until index publication", %{
    repo: repo,
    pid: pid
  } do
    records = %{"a" => %{id: "a"}, "b" => %{id: "b"}}

    Agent.update(
      pid,
      &%{&1 | disk: %{tasks: {:ok, records}}, fail: Records.record_key(repo, "b")}
    )

    assert {:error, {:migration, :disk_full}} = Records.load(repo, &decode/2)
    assert {:ok, ^records} = Adapter.get_checkpoint(:tasks, pid: pid)
    Agent.update(pid, &%{&1 | fail: nil})
    assert {:ok, ^records} = Records.load(repo, &decode/2)
    assert {:ok, %{version: 2, ids: ["a", "b"]}} = Adapter.get_checkpoint(:tasks, pid: pid)
  end

  test "failed publication removes the orphan; ambiguous publication never rolls back", %{
    repo: repo,
    pid: pid
  } do
    Agent.update(pid, &%{&1 | fail: :tasks})
    assert {:error, :disk_full} = Records.put(repo, %{}, "a", %{id: "a"})
    assert :not_found = Adapter.get_checkpoint(Records.record_key(repo, "a"), pid: pid)
    Agent.update(pid, &%{&1 | error: {:error, {:commit_outcome_unknown, :directory_sync}}})

    assert {:error, {:commit_outcome_unknown, :directory_sync}} =
             Records.put(repo, %{}, "a", %{id: "a"})

    assert {:ok, %{"a" => %{id: "a"}}} = Records.load(repo, &decode/2)

    assert {:stop, {:commit_outcome_unknown, :directory_sync}, _, :old} =
             Records.reply({:error, {:commit_outcome_unknown, :directory_sync}}, :ok, :old, :new)
  end

  @tag capture_log: true
  test "a corrupt record is quarantined without blocking its peers", %{repo: repo, pid: pid} do
    assert :ok = Records.put(repo, %{}, "a", %{id: "a"})
    assert :ok = Records.put(repo, %{"a" => %{id: "a"}}, "b", %{id: "b"})
    key = Records.record_key(repo, "a")
    Agent.update(pid, &%{&1 | disk: Map.put(&1.disk, key, {:error, :corrupt})})
    assert {:ok, %{"b" => %{id: "b"}}} = Records.load(repo, &decode/2)
    assert {:ok, %{ids: ["b"]}} = Adapter.get_checkpoint(:tasks, pid: pid)
    assert {:error, :corrupt} = Adapter.get_checkpoint(key, pid: pid)
  end

  test "deletion keeps record bytes until index publication and never resurrects an orphan", %{
    repo: repo,
    pid: pid
  } do
    records = %{"a" => %{id: "a"}, "b" => %{id: "b"}}
    assert :ok = Records.put(repo, %{}, "a", records["a"])
    assert :ok = Records.put(repo, Map.take(records, ["a"]), "b", records["b"])
    Agent.update(pid, &%{&1 | fail: :tasks})

    assert {:error, :disk_full} = Records.drop(repo, records, ["a"])
    assert {:ok, ^records} = Records.load(repo, &decode/2)

    Agent.update(pid, &%{&1 | error: {:error, {:commit_outcome_unknown, :directory_sync}}})

    assert {:error, {:commit_outcome_unknown, :directory_sync}} =
             Records.drop(repo, records, ["a"])

    # The adapter published the index, but its directory-sync answer was lost. Keep
    # the bytes for reconciliation; a restarted owner follows the committed index.
    assert {:ok, %{"a" => %{id: "a"}}} =
             Adapter.get_checkpoint(Records.record_key(repo, "a"), pid: pid)

    assert {:ok, %{"b" => %{id: "b"}}} = Records.load(repo, &decode/2)
  end
end
