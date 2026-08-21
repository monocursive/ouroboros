defmodule Ouroboros.WorkspaceTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Workspace
  alias Ouroboros.Workspace.Path, as: WorkspacePath

  setup do
    base =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-workspace-test-#{System.unique_integer([:positive, :monotonic])}"
      )

    allowed = Path.join(base, "allowed")
    nested = Path.join(allowed, "nested")
    outside = Path.join(base, "outside")

    File.mkdir_p!(nested)
    File.mkdir_p!(outside)

    manager =
      start_supervised!(
        {Workspace,
         allowed_roots: [allowed],
         name: nil,
         id: {:workspace_manager, System.unique_integer([:positive, :monotonic])}}
      )

    {:ok, canonical_allowed} = WorkspacePath.canonicalize(allowed)
    {:ok, canonical_nested} = WorkspacePath.canonicalize(nested)
    {:ok, canonical_outside} = WorkspacePath.canonicalize(outside)

    on_exit(fn -> File.rm_rf!(base) end)

    {:ok,
     manager: manager,
     base: base,
     allowed: canonical_allowed,
     nested: canonical_nested,
     outside: canonical_outside}
  end

  test "canonical admission rejects traversal and symbolic-link escape", context do
    %{manager: manager, allowed: allowed, nested: nested, outside: outside} = context

    assert {:ok, ^nested} = Workspace.validate_root(nested <> "/.", server: manager)

    traversal = allowed <> "/../outside"

    assert {:error, {:workspace_outside_allowed_roots, ^outside, [^allowed]}} =
             Workspace.validate_root(traversal, server: manager)

    escape = Path.join(allowed, "escape")
    File.ln_s!(outside, escape)

    assert {:error, {:workspace_outside_allowed_roots, ^outside, [^allowed]}} =
             Workspace.acquire(escape, "escaped-task", server: manager)

    target = Path.join(outside, "target")
    sibling = Path.join(outside, "sibling")
    File.mkdir_p!(target)
    File.mkdir_p!(sibling)
    escape_with_parent = Path.join(allowed, "escape-with-parent")
    File.ln_s!(target, escape_with_parent)

    # Resolving `..` before the symlink would incorrectly leave this path under
    # `allowed`; filesystem resolution reaches `outside/sibling` instead.
    assert {:error, {:workspace_outside_allowed_roots, ^sibling, [^allowed]}} =
             Workspace.validate_root(escape_with_parent <> "/../sibling", server: manager)
  end

  test "file canonicalization follows the leaf symlink for containment checks", context do
    %{allowed: allowed, outside: outside} = context
    inside_file = Path.join(allowed, "inside.txt")
    outside_file = Path.join(outside, "outside.txt")
    escape = Path.join(allowed, "file-escape")
    File.write!(inside_file, "inside")
    File.write!(outside_file, "outside")
    File.ln_s!(outside_file, escape)

    assert {:ok, ^inside_file} = WorkspacePath.canonicalize_file(inside_file)
    assert {:ok, ^outside_file} = WorkspacePath.canonicalize_file(escape)
    assert WorkspacePath.within?(inside_file, allowed)
    refute WorkspacePath.within?(outside_file, allowed)

    assert {:error, {:not_a_regular_file, ^allowed}} =
             WorkspacePath.canonicalize_file(allowed)
  end

  test "shared reads coexist while exclusive leases exclude overlapping roots", context do
    %{manager: manager, allowed: allowed, nested: nested} = context

    assert {:ok, first, _first_capability} =
             Workspace.acquire(allowed, "reader-1", server: manager, mode: :shared_read)

    assert {:ok, second, _second_capability} =
             Workspace.acquire(nested, "reader-2", server: manager, mode: :shared_read)

    assert {:error, {:workspace_conflict, conflicts}} =
             Workspace.acquire(nested, "writer", server: manager, mode: :exclusive)

    assert Enum.sort(Enum.map(conflicts, & &1.id)) == Enum.sort([first.id, second.id])
    assert Enum.all?(conflicts, &(&1.mode == :shared_read))

    assert :ok = Workspace.release(first, server: manager)
    assert :ok = Workspace.release(first, server: manager)
    assert :ok = Workspace.release(second, server: manager)

    assert {:ok, writer, _capability} =
             Workspace.acquire(allowed, "writer", server: manager, mode: :exclusive)

    assert {:error, {:workspace_conflict, [%{id: writer_id}]}} =
             Workspace.acquire(nested, "reader-3", server: manager, mode: :shared_read)

    assert writer_id == writer.id
  end

  test "owner death automatically releases its leases", %{manager: manager, allowed: allowed} do
    parent = self()

    owner =
      spawn(fn ->
        result = Workspace.acquire(allowed, "ephemeral-owner", server: manager)
        send(parent, {:lease_acquired, self(), result})
        Process.sleep(:infinity)
      end)

    assert_receive {:lease_acquired, ^owner, {:ok, lease, _capability}}, 1_000
    assert [%{id: lease_id}] = Workspace.list(server: manager)
    assert lease_id == lease.id

    Process.exit(owner, :kill)
    assert_eventually(fn -> Workspace.list(server: manager) == [] end)

    assert {:ok, replacement, _capability} =
             Workspace.acquire(allowed, "replacement", server: manager, mode: :exclusive)

    assert replacement.root == allowed
  end

  test "only the owner or capability holder gets idempotent release", %{
    manager: manager,
    allowed: allowed
  } do
    parent = self()

    owner =
      spawn(fn ->
        {:ok, lease, capability} =
          Workspace.acquire(allowed, "delegated-release", server: manager)

        send(parent, {:delegated_lease, lease, capability})
        Process.sleep(:infinity)
      end)

    assert_receive {:delegated_lease, lease, capability}, 1_000

    assert {:error, :not_lease_owner} = Workspace.release(lease, server: manager)
    assert :ok = Workspace.release(lease, server: manager, capability: capability)
    assert :ok = Workspace.release(lease, server: manager, capability: capability)

    assert {:error, :not_lease_owner} =
             Workspace.release(lease, server: manager, capability: "wrong")

    assert {:ok, %{id: lease_id, status: :released}} =
             Workspace.status(lease, server: manager)

    assert lease_id == lease.id
    Process.exit(owner, :kill)
  end

  test "inspection records contain no process identifiers or capabilities", %{
    manager: manager,
    allowed: allowed
  } do
    assert {:ok, lease, capability} =
             Workspace.acquire(allowed, "inspectable", server: manager)

    assert [%{id: id, owner: %{type: :local_process}} = public] =
             Workspace.list(server: manager)

    assert id == lease.id
    refute contains_pid?(public)
    refute inspect(public) =~ capability

    assert %{active_lease_count: 1, leases: [summary_lease]} =
             Workspace.summary(server: manager)

    refute contains_pid?(summary_lease)
  end

  test "a recovery reservation cannot be claimed by spoofing its durable task id", %{
    manager: manager,
    allowed: allowed
  } do
    task_id = "reserved-coding-task"

    lease = %Ouroboros.Workspace.Lease{
      id: "reserved-lease",
      root: allowed,
      task_id: task_id,
      mode: :exclusive,
      owner: %{id: "reserved-owner", node: node(), type: :local_process},
      acquired_at: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    :sys.replace_state(manager, fn state ->
      reservation = %Ouroboros.Workspace.Manager.Reservation{kind: :coding, lease: lease}
      %{state | reservations: %{{:coding, task_id} => reservation}}
    end)

    assert {:error, {:workspace_recovery_owner_mismatch, ^task_id}} =
             Workspace.acquire_managed(allowed, task_id, :coding,
               server: manager,
               mode: :exclusive
             )

    assert {:error, {:workspace_conflict, [%{id: "reserved-lease", task_id: ^task_id}]}} =
             Workspace.acquire(allowed, "other-task", server: manager, mode: :exclusive)
  end

  test "coding and interactive recovery identities cannot collide through rendered ids", %{
    manager: manager,
    allowed: allowed
  } do
    rendered_id = "interactive:shared-id"

    coding = %Ouroboros.Workspace.Lease{
      id: "coding-reservation",
      root: allowed,
      task_id: rendered_id,
      mode: :shared_read,
      owner: %{id: "coding-owner", node: node(), type: :local_process},
      acquired_at: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    interactive = %{
      coding
      | id: "interactive-reservation",
        owner: %{coding.owner | id: "interactive-owner"}
    }

    :sys.replace_state(manager, fn state ->
      reservations = %{
        {:coding, rendered_id} => %Ouroboros.Workspace.Manager.Reservation{
          kind: :coding,
          lease: coding
        },
        {:interactive, "shared-id"} => %Ouroboros.Workspace.Manager.Reservation{
          kind: :interactive,
          lease: interactive
        }
      }

      %{state | reservations: reservations}
    end)

    assert %{recovery_reservation_count: 2} = Workspace.summary(server: manager)

    assert Enum.sort(Enum.map(Workspace.list(server: manager), & &1.id)) == [
             "coding-reservation",
             "interactive-reservation"
           ]

    assert {:error, {:workspace_recovery_owner_mismatch, ^rendered_id}} =
             Workspace.acquire_managed(allowed, rendered_id, :coding,
               server: manager,
               mode: :shared_read
             )

    assert %{recovery_reservation_count: 2} = Workspace.summary(server: manager)

    assert {:error, {:workspace_conflict, conflicts}} =
             Workspace.acquire(allowed, rendered_id, server: manager, mode: :exclusive)

    assert Enum.sort(Enum.map(conflicts, & &1.id)) == [
             "coding-reservation",
             "interactive-reservation"
           ]
  end

  test "public API rejects malformed options and lease handles without raising", %{
    manager: manager,
    allowed: allowed
  } do
    assert {:error, {:invalid_workspace_options, %{server: manager}}} =
             Workspace.acquire(allowed, "bad-options", %{server: manager})

    assert {:error, {:unknown_workspace_option, :typo}} =
             Workspace.acquire(allowed, "bad-options", server: manager, typo: true)

    assert {:error, {:invalid_workspace_lease, %{id: "map-is-not-a-lease"}}} =
             Workspace.release(%{id: "map-is-not-a-lease"}, server: manager)

    assert {:error, {:invalid_workspace_lease, ""}} =
             Workspace.status("", server: manager)

    assert {:error, {:invalid_interactive_workspace_task_id, "not-prefixed"}} =
             Workspace.acquire_managed(allowed, "not-prefixed", :interactive, server: manager)

    assert Process.alive?(manager)
  end

  test "released tombstones are bounded and evict oldest first", %{allowed: allowed} do
    manager =
      start_supervised!(
        {Workspace,
         allowed_roots: [allowed],
         name: nil,
         id: {:workspace_manager, System.unique_integer([:positive, :monotonic])},
         released_tombstone_limit: 3}
      )

    released_ids =
      for index <- 1..5 do
        assert {:ok, lease, _capability} =
                 Workspace.acquire(allowed, "tombstone-#{index}", server: manager)

        :ok = Workspace.release(lease, server: manager)
        lease.id
      end

    [first_evicted, second_evicted | retained] = released_ids

    for evicted <- [first_evicted, second_evicted] do
      assert {:error, :lease_not_found} = Workspace.status(evicted, server: manager)
      assert {:error, :lease_not_found} = Workspace.release(evicted, server: manager)
    end

    for lease_id <- retained do
      assert {:ok, %{status: :released}} = Workspace.status(lease_id, server: manager)
    end
  end

  defp assert_eventually(fun, attempts \\ 100)
  defp assert_eventually(_fun, 0), do: flunk("condition did not become true")

  defp assert_eventually(fun, attempts) do
    if fun.() do
      :ok
    else
      Process.sleep(10)
      assert_eventually(fun, attempts - 1)
    end
  end

  defp contains_pid?(value) when is_pid(value), do: true

  defp contains_pid?(value) when is_map(value),
    do: Enum.any?(value, fn {key, val} -> contains_pid?(key) or contains_pid?(val) end)

  defp contains_pid?(value) when is_list(value), do: Enum.any?(value, &contains_pid?/1)
  defp contains_pid?(value) when is_tuple(value), do: value |> Tuple.to_list() |> contains_pid?()
  defp contains_pid?(_value), do: false
end
