defmodule Ouroboros.Gateway.WireTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Gateway.Wire
  alias Ouroboros.Orchestration.Serializable

  defmodule Sample do
    @moduledoc false
    defstruct [:id, :at, :pid, :nested]
  end

  defp roundtrip(term), do: term |> Wire.to_json() |> JSON.encode!() |> JSON.decode!()

  describe "the shape safe/1 would have destroyed" do
    test "a pid beside readable siblings costs only the pid" do
      # This is `Mesh.list_agents/0`'s exact return shape, which `Ouroboros.status/0`
      # embeds. `Serializable.safe/1` replaces the whole list with one inspect string;
      # the dashboard's entire data source would be that string.
      agents = [%{id: "a", pid: self(), node: node(), replicas: 1}]

      assert {:unserializable, _rendered} = Serializable.safe(agents)

      assert [agent] = roundtrip(agents)
      assert agent["id"] == "a"
      assert agent["node"] == Atom.to_string(node())
      assert agent["replicas"] == 1
      assert agent["pid"]["_opaque"] =~ "#PID<"
    end

    test "opaque leaves are opaque one at a time, however deeply nested" do
      term = %{
        outer: [%{inner: {self(), make_ref()}}],
        port: Port.list() |> List.first(),
        fun: &Wire.to_json/1,
        keep: "readable"
      }

      encoded = roundtrip(term)

      assert encoded["keep"] == "readable"
      assert [%{"inner" => [pid, ref]}] = encoded["outer"]
      assert pid["_opaque"] =~ "#PID<"
      assert ref["_opaque"] =~ "#Reference<"
      assert encoded["port"]["_opaque"] =~ "#Port<"
      assert encoded["fun"]["_opaque"] == "&Ouroboros.Gateway.Wire.to_json/1"
    end
  end

  describe "leaf rules" do
    test "tuples become lists and atoms become strings" do
      assert roundtrip({:ok, :available, 3}) == ["ok", "available", 3]
      assert roundtrip(%{status: :running}) == %{"status" => "running"}
    end

    test "module atoms render the way a person writes them" do
      # The client echoes this string back to `upgrade.history`, so what it reads has to
      # be what `String.to_existing_atom/1` can resolve on the other side.
      assert roundtrip(Ouroboros.Gateway.Wire) == "Ouroboros.Gateway.Wire"
      assert roundtrip([:ok, nil, true, false]) == ["ok", nil, true, false]
    end

    test "structs carry their name and recurse" do
      encoded =
        roundtrip(%Sample{
          id: "s1",
          at: ~U[2026-08-13 10:00:00Z],
          pid: self(),
          nested: %Sample{id: "s2", at: ~N[2026-08-13 10:00:00], pid: nil, nested: nil}
        })

      assert encoded["_struct"] == "Ouroboros.Gateway.WireTest.Sample"
      assert encoded["id"] == "s1"
      assert encoded["at"] == "2026-08-13T10:00:00Z"
      assert encoded["nested"]["_struct"] == "Ouroboros.Gateway.WireTest.Sample"
      assert encoded["nested"]["at"] == "2026-08-13T10:00:00"
    end

    test "dates and times are ISO-8601 rather than field bags" do
      assert roundtrip(%{d: ~D[2026-08-13], t: ~T[10:00:00]}) ==
               %{"d" => "2026-08-13", "t" => "10:00:00"}
    end

    test "a binary that is not text is base64 rather than an encoder crash" do
      encoded = roundtrip(%{blob: <<0xFF, 0xFE, 0x00>>, text: "héllo"})

      assert encoded["blob"] == %{"_b64" => Base.encode64(<<0xFF, 0xFE, 0x00>>)}
      assert encoded["text"] == "héllo"
    end

    test "map keys of every kind become strings" do
      assert roundtrip(%{:atom => 1, "binary" => 2, 3 => 4}) ==
               %{"atom" => 1, "binary" => 2, "3" => 4}
    end

    test "an improper tail is named rather than smuggled in as an element" do
      assert [1, %{"_improper_tail" => 2}] = roundtrip([1 | 2])
    end

    test "a queue survives as the tuple of lists it is" do
      queue = :queue.in(:b, :queue.in(:a, :queue.new()))

      assert roundtrip(queue) == [["b"], ["a"]]
    end
  end

  describe "caps" do
    test "depth beyond 32 is truncated visibly, not silently" do
      deep = Enum.reduce(1..40, :bottom, fn _index, acc -> %{next: acc} end)

      truncation =
        Enum.reduce_while(1..40, roundtrip(deep), fn _index, node ->
          case node do
            %{"next" => next} -> {:cont, next}
            other -> {:halt, other}
          end
        end)

      assert truncation == %{"_truncated" => true}
    end

    test "a term wider than the node budget is truncated, and the encoder still returns" do
      wide = Enum.map(1..60_000, &%{index: &1})

      encoded = roundtrip(wide)

      assert length(encoded) < 60_000
      assert List.last(encoded) == %{"_truncated" => true}
    end

    test "the budget is per encode, so one big payload does not shrink the next" do
      wide = Enum.map(1..60_000, &%{index: &1})
      _first = Wire.to_json(wide)

      assert Wire.to_json(%{a: 1}) == %{"a" => 1}
    end
  end

  describe "frames" do
    test "one frame is one line" do
      frame = Wire.frame!(%{"jsonrpc" => "2.0", "id" => 1}) |> IO.iodata_to_binary()

      assert String.ends_with?(frame, "\n")

      assert frame |> String.trim_trailing("\n") |> JSON.decode!() == %{
               "jsonrpc" => "2.0",
               "id" => 1
             }
    end
  end

  test "a live agent-server state encodes without losing the parts a client renders" do
    # The dense case the spec calls out: pids, refs, queues, and functions in one struct.
    state = %{
      __struct__: Jido.AgentServer.State,
      agent: %{id: "agent-1", state: %{counter: 3}},
      status: :idle,
      pending_signals: :queue.new(),
      reply_refs: %{make_ref() => self()},
      dispatch: {:pid, [target: self()]}
    }

    encoded = roundtrip(state)

    assert encoded["_struct"] == "Jido.AgentServer.State"
    assert encoded["status"] == "idle"
    assert encoded["agent"]["state"]["counter"] == 3
    assert encoded["dispatch"] == ["pid", [["target", %{"_opaque" => inspect(self())}]]]
  end
end
