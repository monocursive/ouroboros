defmodule Ouroboros.Maintenance.NativeInventoryTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Maintenance.NativeInventory

  defmodule SessionFixture do
    def prepare_fence(pid, generation, token),
      do:
        Agent.get_and_update(pid, fn state ->
          {state.prepare, %{state | calls: [{:prepare, generation, token} | state.calls]}}
        end)

    def release_fence(pid, generation, token),
      do:
        Agent.get_and_update(pid, fn state ->
          {:ok, %{state | calls: [{:release, generation, token} | state.calls]}}
        end)

    def revalidate_fence(pid, generation, token, root),
      do:
        Agent.get_and_update(pid, fn state ->
          {state.revalidate,
           %{state | calls: [{:revalidate, generation, token, root} | state.calls]}}
        end)
  end

  test "freezes sorted participants and returns exact release capability" do
    token = make_ref()
    b = agent({:ok, row("b", "runtime-b", "provider-b", 4)})
    a = agent({:ok, row("a", "runtime-a", "provider-a", 4)})

    assert {:ok, snapshot} =
             NativeInventory.snapshot(4,
               maintenance_token: token,
               participants: [{"b", b}, {"a", a}],
               native_session_module: SessionFixture
             )

    assert Enum.map(snapshot.rows, & &1.logical_id) == ["a", "b"]
    assert snapshot.release.generation == 4
    assert snapshot.release.token == token
    assert :ok = NativeInventory.release(snapshot.release)
    assert [{:release, 4, ^token}, {:prepare, 4, ^token}] = Agent.get(a, & &1.calls)
  end

  test "partial prepare failure releases only already prepared participants" do
    token = make_ref()
    first = agent({:ok, row("a", "runtime-a", "provider-a", 2)})
    second = agent({:error, :active_turn})

    assert {:error, :active_turn} =
             NativeInventory.snapshot(2,
               maintenance_token: token,
               participants: [{"a", first}, {"b", second}],
               native_session_module: SessionFixture
             )

    assert [{:release, 2, ^token}, {:prepare, 2, ^token}] = Agent.get(first, & &1.calls)
    assert [{:prepare, 2, ^token}] = Agent.get(second, & &1.calls)
  end

  test "requires exact token generation and registry identity" do
    pid = agent({:ok, row("other", "runtime-a", "provider-a", 3)})
    assert {:error, :native_fence_token_required} = NativeInventory.snapshot(3, participants: [])

    assert {:error, :native_identity_mismatch} =
             NativeInventory.snapshot(3,
               maintenance_token: make_ref(),
               participants: [{"expected", pid}],
               native_session_module: SessionFixture
             )
  end

  test "revalidation fails closed when the frozen participant dies or is replaced" do
    token = make_ref()
    pid = agent({:ok, row("a", "runtime-a", "provider-a", 5)})

    release = %{
      generation: 5,
      token: token,
      participants: [{"a", pid}],
      session_module: SessionFixture
    }

    expected = [row("a", "runtime-a", "provider-a", 5)]
    Agent.update(pid, &Map.put(&1, :revalidate, {:ok, hd(expected)}))
    assert :ok = NativeInventory.revalidate(release, expected)

    Process.exit(pid, :kill)
    ref = Process.monitor(pid)
    assert_receive {:DOWN, ^ref, :process, ^pid, reason}
    assert reason in [:killed, :noproc]

    assert {:error, {:native_participant_died, "a"}} =
             NativeInventory.revalidate(release, expected)

    replacement = agent({:ok, hd(expected)})
    replacement_release = %{release | participants: [{"a", replacement}]}
    Agent.update(replacement, &Map.put(&1, :revalidate, {:error, :stale_native_fence}))

    assert {:error, :stale_native_fence} =
             NativeInventory.revalidate(replacement_release, expected)
  end

  defp agent(prepare) do
    {:ok, pid} = Agent.start(fn -> %{prepare: prepare, revalidate: prepare, calls: []} end)
    pid
  end

  defp row(logical, runtime, provider, generation) do
    %{
      logical_id: logical,
      runtime_id: runtime,
      provider_session_id: provider,
      process_generation: 1,
      fence_generation: generation,
      lifecycle: :idle,
      active_count: 0,
      queued_count: 0,
      unresolved_count: 0,
      checkpoint: %{sha256: String.duplicate("a", 64), bytes: 1, device: 1, inode: 1, mtime: 1},
      journal: %{
        sha256: String.duplicate("b", 64),
        bytes: 1,
        device: 1,
        inode: 1,
        mtime: 1,
        head: String.duplicate("c", 64),
        sequence: 1
      },
      handoff: %{absent: true},
      root_digest: String.duplicate("d", 64)
    }
  end
end
