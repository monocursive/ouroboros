defmodule Ouroboros.Maintenance.InventoryTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Maintenance.Inventory

  @local "nonode@nohost"

  test "sorts deterministically and terminal digest length-frames the complete inventory" do
    rows = [item("z", "z-data"), item("a", "a-data")]
    {:ok, snapshot} = freeze(rows)

    assert Enum.map(snapshot.items, & &1.session_id) == ["a", "z"]
    assert snapshot.total == 2

    assert {:ok, page} = Inventory.page(snapshot, snapshot.token, nil, 100, 7)
    assert page.complete
    assert page.next_cursor == nil
    assert page.digest == snapshot.digest

    encoded = snapshot.encoded_items
    expected = sha(["OUROBOROS-P4-INVENTORY-V1\0" | Enum.map(encoded, &frame/1)])
    assert page.digest == expected

    # Ambiguous concatenation would collide; framing and item field framing do not.
    {:ok, one} = freeze([item("ab", "c")])
    {:ok, two} = freeze([item("a", "bc")])
    refute one.digest == two.digest

    {:ok, reordered} = freeze(Enum.reverse(rows))
    assert reordered.digest == snapshot.digest
    assert reordered.token == snapshot.token
  end

  test "pages at at most 100 and binds cursors to snapshot, generation and total" do
    rows = for n <- 1..205, do: item(String.pad_leading(Integer.to_string(n), 3, "0"), "data")
    {:ok, snapshot} = freeze(Enum.reverse(rows))

    assert {:error, :invalid_page_limit} = Inventory.page(snapshot, snapshot.token, nil, 101, 7)
    assert {:ok, first} = Inventory.page(snapshot, snapshot.token, nil, 100, 7)
    assert length(first.items) == 100
    refute first.complete
    assert first.digest == nil

    assert {:ok, second} = Inventory.page(snapshot, snapshot.token, first.next_cursor, 100, 7)
    assert length(second.items) == 100
    refute second.complete

    assert {:ok, last} = Inventory.page(snapshot, snapshot.token, second.next_cursor, 100, 7)
    assert length(last.items) == 5
    assert last.complete
    assert last.digest == snapshot.digest

    assert Enum.map(first.items ++ second.items ++ last.items, & &1.session_id) ==
             Enum.map(snapshot.items, & &1.session_id)

    tampered_cursor = flip_last(first.next_cursor)

    assert {:error, :invalid_cursor} =
             Inventory.page(snapshot, snapshot.token, tampered_cursor, 10, 7)

    assert {:error, :snapshot_token_mismatch} =
             Inventory.page(snapshot, String.duplicate("0", 64), nil, 10, 7)

    assert {:error, :generation_mismatch} = Inventory.page(snapshot, snapshot.token, nil, 10, 8)

    {:ok, other} = freeze(Enum.drop(rows, -1))

    assert {:error, :invalid_cursor} =
             Inventory.page(other, other.token, first.next_cursor, 10, 7)
  end

  test "snapshot validation detects value, token, generation and root tampering" do
    {:ok, snapshot} = freeze([item("one", "data")])

    for forged <- [
          %{snapshot | token: String.duplicate("0", 64)},
          %{snapshot | generation: 8},
          %{snapshot | root_digest: digest("other-root")},
          %{snapshot | items: [%{hd(snapshot.items) | checkpoint_length: 999}]}
        ] do
      assert {:error, :invalid_snapshot} =
               Inventory.page(forged, forged.token, nil, 1, forged.generation)
    end
  end

  test "refuses unbounded inventories and fields, extras, and duplicate session IDs" do
    assert {:error, :inventory_capacity} =
             freeze([item("a", "a"), item("b", "b")], max_items: 1)

    assert {:error, :invalid_inventory_bound} = freeze([], max_items: 10_001)
    assert {:error, :invalid_item_shape} = freeze([Map.put(item("a", "a"), :extra, true)])
    assert {:error, :invalid_item_shape} = freeze([Map.delete(item("a", "a"), :lifecycle)])
    assert {:error, :invalid_text} = freeze([item(String.duplicate("x", 129), "a")])

    assert {:error, :invalid_checkpoint_length} =
             freeze([%{item("a", "a") | checkpoint_length: 2_199_023_255_552}])

    assert {:error, :invalid_handoff} =
             freeze([%{item("a", "a") | handoff_lineage: List.duplicate(lineage("p"), 65)}])

    assert {:error, :duplicate_session_id} = freeze([item("same", "a"), item("same", "b")])
  end

  test "refuses remote ownership, remote handoff, and nonidle or nonzero work" do
    assert {:error, :remote_owner} = freeze([%{item("a", "a") | owner_node: "peer@host"}])

    assert {:error, :remote_handoff} =
             freeze([
               %{item("a", "a") | handoff_lineage: [%{lineage("parent") | node: "peer@host"}]}
             ])

    assert {:error, :nonidle_item} = freeze([%{item("a", "a") | lifecycle: :running}])
    assert {:error, :nonzero_work} = freeze([%{item("a", "a") | active_count: 1}])
    assert {:error, :nonzero_work} = freeze([%{item("a", "a") | queued_count: 1}])
  end

  test "requires an exact reservation inventory with no missing or extra reservation" do
    reserved = item("a", "a", reservation: reservation("a"))
    idle = item("b", "b")

    assert {:ok, _snapshot} =
             freeze([reserved, idle], reservations: %{"a" => reservation("a"), "b" => nil})

    assert {:error, :reservation_mismatch} =
             freeze([reserved, idle], reservations: %{"a" => reservation("a")})

    assert {:error, :reservation_mismatch} =
             freeze([reserved, idle],
               reservations: %{"a" => reservation("a"), "b" => nil, "extra" => nil}
             )

    assert {:error, :reservation_mismatch} =
             freeze([reserved, idle],
               reservations: %{"a" => %{reservation("a") | root: "/different"}, "b" => nil}
             )

    mismatched = %{reserved | workspace_reservation: %{reservation("a") | session_id: "other"}}

    assert {:error, :reservation_mismatch} =
             freeze([mismatched], reservations: %{"a" => reservation("a")})
  end

  defp freeze(rows, overrides \\ []) do
    reservations = Map.new(rows, fn row -> {row.session_id, row.workspace_reservation} end)

    Inventory.freeze(
      rows,
      Keyword.merge(
        [
          local_node: @local,
          generation: 7,
          root_digest: digest("root"),
          reservations: reservations
        ],
        overrides
      )
    )
  end

  defp item(id, checkpoint, opts \\ []) do
    %{
      session_id: id,
      generation: 3,
      checkpoint_sha256: digest(checkpoint),
      checkpoint_length: byte_size(checkpoint),
      owner_node: @local,
      process_generation: 2,
      lifecycle: :idle,
      active_count: 0,
      queued_count: 0,
      workspace_reservation: Keyword.get(opts, :reservation),
      handoff_lineage: []
    }
  end

  defp reservation(session_id),
    do: %{session_id: session_id, generation: 3, root: "/tmp/#{session_id}"}

  defp lineage(session_id), do: %{session_id: session_id, node: @local}
  defp digest(value), do: :crypto.hash(:sha256, value) |> Base.encode16(case: :lower)
  defp sha(iodata), do: :crypto.hash(:sha256, iodata) |> Base.encode16(case: :lower)
  defp frame(value), do: [<<IO.iodata_length(value)::unsigned-big-32>>, value]

  defp flip_last(value) do
    size = byte_size(value) - 1
    <<prefix::binary-size(^size), last>> = value
    prefix <> <<Bitwise.bxor(last, 1)>>
  end
end
