defmodule Ouroboros.Maintenance.FenceTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Maintenance.Fence

  @snapshot_id String.duplicate("a", 64)
  @inventory_digest String.duplicate("b", 64)
  @root_digest String.duplicate("c", 64)

  setup do
    root = Path.join(System.tmp_dir!(), "maintenance-fence-#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf(root) end)
    %{root: root}
  end

  test "closes admission before the barrier, persists its identity, and restarts exactly closed",
       %{
         root: root
       } do
    parent = self()
    barrier_value = barrier_value(1, write_epoch: 23)

    barrier = fn generation, opts ->
      send(parent, {:barrier_called, self(), generation, opts})

      receive do
        :continue -> {:ok, barrier_value}
      end
    end

    {:ok, first} =
      start_supervised(
        {Fence,
         name: :fence_integrated,
         data_dir: root,
         barrier: barrier,
         barrier_opts: [source: :isolated]},
        id: :fence_integrated_child
      )

    enter = Task.async(fn -> Fence.enter("tx-1", 0, :fence_integrated) end)

    assert_receive {:barrier_called, worker, 1, opts}
    assert opts[:source] == :isolated
    assert is_reference(opts[:maintenance_token])

    assert %{state: :closing, generation: 0, transaction_id: "tx-1"} =
             Fence.inspect(:fence_integrated)

    assert {:error, :maintenance_fenced} =
             Fence.acquire("op-closing", "session", :fence_integrated)

    send(worker, :continue)
    assert_receive {:barrier_called, ^worker, 1, second_opts}
    assert second_opts == opts
    send(worker, :continue)

    assert {:ok, marker} = Task.await(enter)
    assert marker["generation"] == 1
    assert marker["snapshot_id"] == @snapshot_id
    assert marker["inventory_digest"] == @inventory_digest
    assert marker["write_epoch"] == 23

    path = Path.join(root, "maintenance-fence.json")
    assert File.stat!(path).mode |> Bitwise.band(0o777) == 0o600
    assert {:ok, ^marker} = path |> File.read!() |> Jason.decode()

    assert {:error, :maintenance_fenced} =
             Fence.acquire("op-fenced", "session", :fence_integrated)

    GenServer.stop(first)
    start_supervised!({Fence, name: :fence_restarted, data_dir: root})

    assert %{state: :fenced, generation: 1, transaction_id: "tx-1"} =
             Fence.inspect(:fence_restarted)

    assert {:error, :fence_identity_mismatch} =
             Fence.release_fence("other", 1, :fence_restarted)

    assert :ok = Fence.release_fence("tx-1", 1, :fence_restarted)
    assert %{state: :open, generation: 1} = Fence.inspect(:fence_restarted)
    assert {:ok, %{generation: 1}} = Fence.acquire("after", "session", :fence_restarted)
  end

  test "barrier refusal reopens admission and does not publish a marker", %{root: root} do
    barrier = fn _generation, _opts -> {:error, :nonterminal_session} end
    start_supervised!({Fence, name: :fence_refusal, data_dir: root, barrier: barrier})

    assert {:error, {:barrier_refused, :nonterminal_session}} =
             Fence.enter("tx", 0, :fence_refusal)

    assert %{state: :open, generation: 0} = Fence.inspect(:fence_refusal)
    assert {:ok, _token} = Fence.acquire("op", "session", :fence_refusal)
    refute File.exists?(Path.join(root, "maintenance-fence.json"))
  end

  test "revalidation refuses a changed participant snapshot", %{root: root} do
    parent = self()

    barrier = fn generation, _opts ->
      count = Process.get(:barrier_calls, 0) + 1
      Process.put(:barrier_calls, count)
      send(parent, {:freeze_pass, count})
      suffix = if count == 1, do: "b", else: "d"
      {:ok, barrier_value(generation, inventory_digest: String.duplicate(suffix, 64))}
    end

    start_supervised!({Fence, name: :fence_revalidation, data_dir: root, barrier: barrier})

    assert {:error, {:barrier_refused, :participants_changed}} =
             Fence.enter("tx", 0, :fence_revalidation)

    assert_receive {:freeze_pass, 1}
    assert_receive {:freeze_pass, 2}
    assert %{state: :open, generation: 0} = Fence.inspect(:fence_revalidation)
    refute File.exists?(Path.join(root, "maintenance-fence.json"))
  end

  test "post-snapshot revalidation refuses a changed authority root", %{root: root} do
    barrier = fn generation, _opts ->
      count = Process.get(:root_calls, 0) + 1
      Process.put(:root_calls, count)

      {:ok,
       barrier_value(generation,
         root_digest: String.duplicate(if(count == 1, do: "c", else: "e"), 64)
       )}
    end

    start_supervised!({Fence, name: :fence_root_revalidation, data_dir: root, barrier: barrier})

    assert {:error, {:barrier_refused, :participants_changed}} =
             Fence.enter("tx-root", 0, :fence_root_revalidation)

    assert %{state: :open, generation: 0} = Fence.inspect(:fence_root_revalidation)
    refute File.exists?(Path.join(root, "maintenance-fence.json"))
  end

  test "active admissions and stale generations refuse before calling the barrier", %{root: root} do
    parent = self()

    barrier = fn generation, _opts ->
      send(parent, {:unexpected_barrier, generation})
      {:ok, barrier_value(generation)}
    end

    start_supervised!({Fence, name: :fence_preconditions, data_dir: root, barrier: barrier})
    assert {:ok, token} = Fence.acquire("op-1", "session-1", :fence_preconditions)

    assert {:error, {:active_admission, 1}} =
             Fence.enter("tx-active", 0, :fence_preconditions)

    assert :ok = Fence.release(token, :fence_preconditions)

    assert {:error, {:stale_generation, 0}} =
             Fence.enter("tx-stale", 1, :fence_preconditions)

    refute_receive {:unexpected_barrier, _generation}
    refute File.exists?(Path.join(root, "maintenance-fence.json"))
  end

  test "stable operation IDs and generation-bound capabilities retain admission semantics", %{
    root: root
  } do
    start_supervised!({Fence, name: :fence_ids, data_dir: root, barrier: successful_barrier()})
    assert {:ok, token} = Fence.acquire_admission("same-op", "one", 0, :fence_ids)
    assert {:ok, ^token} = Fence.acquire_admission("same-op", "one", 0, :fence_ids)
    assert :ok = Fence.validate_admission(token, "one", :fence_ids)
    assert :ok = Fence.queue_turn(token, "turn-1", :fence_ids)
    assert {:error, :invalid_turn_id} = Fence.queue_turn(token, "", :fence_ids)
    assert {:error, :operation_id_conflict} = Fence.acquire("same-op", "two", :fence_ids)

    assert {:error, :invalid_admission} =
             Fence.validate_admission(%{token | capability: make_ref()}, "one", :fence_ids)

    assert {:error, :not_lease_owner} =
             Fence.release(%{token | session_id: "forged"}, :fence_ids)

    assert :ok = Fence.release(token, :fence_ids)
    assert {:error, :stale_admission} = Fence.queue_turn(token, "turn-1", :fence_ids)
    assert :stale = Fence.release(token, :fence_ids)
  end

  test "old and malformed retained markers fail closed instead of being upgraded", %{root: root} do
    path = Path.join(root, "maintenance-fence.json")

    for bytes <- [
          ~s({"schema":1,"transaction_id":"old","generation":1,"state":"fenced"}),
          ~s({"schema":1,"state":"open"})
        ] do
      File.write!(path, bytes)
      previous = Process.flag(:trap_exit, true)

      assert {:error, {:maintenance_fence_unavailable, :invalid_marker}} =
               Fence.start_link(name: nil, data_dir: root)

      receive do
        {:EXIT, _pid, {:maintenance_fence_unavailable, :invalid_marker}} -> :ok
      after
        0 -> :ok
      end

      Process.flag(:trap_exit, previous)
    end
  end

  test "a persistence failure releases the exact prepared Native barrier before reopening", %{
    root: root
  } do
    # A directory created at the marker pathname after startup forces rename to fail after
    # both barrier observations succeed, while still leaving precommit release possible.
    parent = self()
    release = %{generation: 1, token: make_ref(), participants: []}

    barrier = fn generation, _opts ->
      send(parent, {:barrier_snapshot, generation})
      {:ok, Map.put(barrier_value(generation), :native_release, release)}
    end

    start_supervised!({Fence, name: :fence_persist_release, data_dir: root, barrier: barrier})
    File.mkdir_p!(Path.join(root, "maintenance-fence.json"))

    assert {:error, {:fence_persist_failed, _reason}} =
             Fence.enter("tx-persist", 0, :fence_persist_release)

    assert_receive {:barrier_snapshot, 1}
    assert_receive {:barrier_snapshot, 1}
    assert %{state: :open, generation: 0} = Fence.inspect(:fence_persist_release)
  end

  defp successful_barrier do
    fn generation, _opts -> {:ok, barrier_value(generation)} end
  end

  defp barrier_value(generation, opts \\ []) do
    %{
      snapshot: %{
        generation: generation,
        token: Keyword.get(opts, :snapshot_id, @snapshot_id),
        digest: Keyword.get(opts, :inventory_digest, @inventory_digest),
        root_digest: Keyword.get(opts, :root_digest, @root_digest),
        total: 0
      },
      write_epoch: Keyword.get(opts, :write_epoch, 0)
    }
  end
end
