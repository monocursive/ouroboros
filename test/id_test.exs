defmodule Ouroboros.IDTest do
  use ExUnit.Case, async: true
  alias Ouroboros.ID

  test "lowercase UUIDv7 formatting, version, variant and injected timestamp" do
    timestamp = 1_789_041_600_123
    id = ID.generate!(fn -> timestamp end)
    assert id =~ ~r/\A[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/
    assert <<^timestamp::48, 7::4, _random_a::12, 2::2, _random_b::62>> = decode(id)
  end

  test "concurrent IDs at a fixed millisecond retain distinct random tails" do
    timestamp = 1_789_041_600_123

    ids =
      1..10_000
      |> Task.async_stream(fn _ -> ID.generate!(fn -> timestamp end) end)
      |> Enum.map(fn {:ok, id} -> id end)

    assert MapSet.size(MapSet.new(ids)) == 10_000
    assert Enum.all?(ids, fn id -> match?(<<^timestamp::48, _::80>>, decode(id)) end)
  end

  test "a backward clock preserves its timestamp without reusing identifiers or promising order" do
    timestamps = [1000, 1000, 999, 998, 1000]
    ids = Enum.map(timestamps, fn timestamp -> ID.generate!(fn -> timestamp end) end)
    assert MapSet.size(MapSet.new(ids)) == length(timestamps)

    assert Enum.map(ids, fn id ->
             <<timestamp::48, _::80>> = decode(id)
             timestamp
           end) == timestamps
  end

  test "timestamps cannot wrap around the 48 bit representation" do
    for timestamp <- [-1, 0x1000000000000, 1.5] do
      assert_raise ArgumentError, "UUIDv7 timestamp out of range", fn ->
        ID.generate!(fn -> timestamp end)
      end
    end
  end

  defp decode(id), do: id |> String.replace("-", "") |> Base.decode16!(case: :lower)
end
