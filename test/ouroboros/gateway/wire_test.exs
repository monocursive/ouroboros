defmodule Ouroboros.Gateway.WireTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Coding.Event, as: CodingEvent
  alias Ouroboros.Gateway.Wire
  alias Ouroboros.Interactive.Event, as: InteractiveEvent
  alias Ouroboros.Orchestration.Serializable

  defmodule Sample do
    @moduledoc false
    defstruct [:id, :at, :pid, :nested]
  end

  @timestamp "2026-01-01T00:00:00.000000Z"

  defp roundtrip(term), do: term |> Wire.to_json() |> JSON.encode!() |> JSON.decode!()

  defp interactive_event(payload) do
    %InteractiveEvent{
      id: "evt-1",
      session_id: "session-1",
      sequence: 42,
      type: :file_change,
      timestamp: @timestamp,
      payload: payload,
      provider: :codex
    }
  end

  defp coding_event(payload) do
    %CodingEvent{
      id: "evt-2",
      task_id: "task-1",
      sequence: 17,
      type: :file_change,
      timestamp: @timestamp,
      payload: payload,
      provider: :codex
    }
  end

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

  describe "the byte cap on event payloads" do
    # 5 MB is the shape the review named: one `file_change` diff, framed whole on every
    # notification and again on every replay of the same session.
    @diff String.duplicate("a", 5_000_000)

    test "one huge payload leaf is excerpted, and says how much it was" do
      encoded = roundtrip(interactive_event(%{"diff" => @diff, "path" => "lib/foo.ex"}))

      assert %{"_excerpt" => excerpt, "_bytes" => 5_000_000} = encoded["payload"]["diff"]
      assert byte_size(excerpt) == 131_072
      assert String.starts_with?(@diff, excerpt)

      # The sibling is untouched: this is a per-leaf cap, not an all-or-nothing sentinel.
      assert encoded["payload"]["path"] == "lib/foo.ex"
    end

    test "the whole frame stays small enough to be worth having a cap for" do
      frame =
        %{"id" => "s-1", "event" => interactive_event(%{"diff" => @diff})}
        |> Wire.to_json()
        |> Wire.frame!()
        |> IO.iodata_to_binary()

      assert byte_size(frame) < 200_000
    end

    test "the fields a client resyncs by are never excerpted" do
      # `sequence` is the resync cursor and `type` is what a transcript branches on. A cap
      # that reached the envelope would bound the wire by breaking the protocol.
      encoded = roundtrip(interactive_event(%{"diff" => @diff}))

      assert encoded["sequence"] == 42
      assert encoded["type"] == "file_change"
      assert encoded["session_id"] == "session-1"
      assert encoded["timestamp"] == "2026-01-01T00:00:00.000000Z"
      assert encoded["provider"] == "codex"
      assert encoded["_struct"] == "Ouroboros.Interactive.Event"
    end

    test "the coding plane is capped by the same code as the interactive one" do
      encoded = roundtrip(coding_event(%{"diff" => @diff}))

      assert %{"_excerpt" => _excerpt, "_bytes" => 5_000_000} = encoded["payload"]["diff"]
      assert encoded["task_id"] == "task-1"
      assert encoded["sequence"] == 17
      assert encoded["_struct"] == "Ouroboros.Coding.Event"
    end

    test "an excerpt cut inside a multi-byte character is still valid UTF-8" do
      # Every character is two bytes, so a cap of 1025 lands in the middle of one and the
      # cut has to retreat. A client decoding this frame is owed a string it can decode.
      text = String.duplicate("é", 4_000)

      encoded =
        Wire.to_json(interactive_event(%{"text" => text}),
          event_leaf_bytes: 1_025,
          event_payload_bytes: 4_096
        )

      excerpt = encoded["payload"]["text"]["_excerpt"]

      assert String.valid?(excerpt)
      assert byte_size(excerpt) == 1_024
      assert encoded["payload"]["text"]["_bytes"] == 8_000
      assert JSON.decode!(JSON.encode!(encoded)) == encoded
    end

    test "the per-event budget bounds what all of one payload's strings cost together" do
      payload = Map.new(1..6, fn index -> {"f#{index}", String.duplicate("x", 200_000)} end)

      encoded = roundtrip(interactive_event(payload))

      emitted =
        encoded["payload"]
        |> Map.values()
        |> Enum.map(&byte_size(&1["_excerpt"]))
        |> Enum.sum()

      # 512 KiB, exactly: four leaves at the per-leaf cap and then nothing left to spend.
      assert emitted == 524_288
      assert Enum.all?(Map.values(encoded["payload"]), &(&1["_bytes"] == 200_000))
    end

    test "the budget starts over at each event, so a replay is not a shrinking list" do
      events = Enum.map(1..3, fn _index -> interactive_event(%{"diff" => @diff}) end)

      excerpts = Enum.map(roundtrip(events), &byte_size(&1["payload"]["diff"]["_excerpt"]))

      assert excerpts == [131_072, 131_072, 131_072]
    end

    test "a short string is never replaced by a marker larger than itself" do
      payload = %{"pad" => @diff, "status" => "completed", "note" => String.duplicate("n", 512)}

      encoded = roundtrip(interactive_event(payload))

      assert encoded["payload"]["status"] == "completed"
      assert byte_size(encoded["payload"]["note"]) == 512
    end

    test "a non-UTF-8 leaf keeps its own spelling and gains the same size marker" do
      blob = :binary.copy(<<0xFF, 0xFE>>, 500_000)

      encoded = roundtrip(interactive_event(%{"blob" => blob}))

      assert encoded["payload"]["blob"]["_bytes"] == 1_000_000
      assert Base.decode64!(encoded["payload"]["blob"]["_b64"]) == binary_part(blob, 0, 131_072)
    end

    test "the cap reaches only events, so no other result changed shape" do
      # `runtime.status`, an agent's state, and an error's `data` all go through the same
      # walk. None of them is an event and none of them is bounded by bytes.
      assert byte_size(Wire.to_json(%{diff: @diff})["diff"]) == 5_000_000
    end

    test "event_detail's larger cap answers the whole leaf the excerpt came from" do
      encoded =
        Wire.to_json(interactive_event(%{"diff" => @diff}),
          event_leaf_bytes: 8_388_608,
          event_payload_bytes: 8_388_608
        )

      assert encoded["payload"]["diff"] == @diff
    end

    test "a leaf past even the detail cap is excerpted rather than framed whole" do
      encoded =
        Wire.to_json(interactive_event(%{"diff" => @diff}),
          event_leaf_bytes: 1_048_576,
          event_payload_bytes: 8_388_608
        )

      assert byte_size(encoded["payload"]["diff"]["_excerpt"]) == 1_048_576
      assert encoded["payload"]["diff"]["_bytes"] == 5_000_000
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
