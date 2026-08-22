defmodule Ouroboros.Gateway.GoldenTest do
  use ExUnit.Case, async: true

  alias Mix.Tasks.Ouroboros.Gateway.Golden
  alias Ouroboros.Gateway.Wire

  # These files are a contract with a second implementation that cannot run this suite. So
  # what is asserted here is not that they parse — it is that they are still what this
  # build emits. Every frame is re-derived through the live envelope and encoder path and
  # compared to the bytes on disk; a gateway change that alters a payload fails here until
  # `mix ouroboros.gateway.golden` is run and the diff is reviewed.

  test "every fixture on disk is what the live encoder produces for the same term" do
    for {name, frame} <- Golden.fixtures() do
      on_disk = name |> Golden.path() |> File.read!() |> JSON.decode!()

      # `Wire.frame!/1` is what writes the socket. Decoding its output rather than
      # comparing strings is the honest comparison: the file is pretty-printed for review
      # and the wire is one compact line, and both must mean the same thing.
      on_wire = frame |> Wire.frame!() |> IO.iodata_to_binary() |> JSON.decode!()

      assert on_disk == on_wire, "#{name}.json has drifted from the code that produces it"
    end
  end

  test "regenerating writes the same bytes, so a no-op change is a no-op diff" do
    for {name, frame} <- Golden.fixtures() do
      assert File.read!(Golden.path(name)) == IO.iodata_to_binary(Golden.encode(frame)),
             "#{name}.json is not byte-stable; run mix ouroboros.gateway.golden"
    end
  end

  test "the directory holds exactly the fixtures the task declares" do
    declared = Golden.fixtures() |> Enum.map(fn {name, _frame} -> Golden.path(name) end)

    assert Enum.sort(Path.wildcard(Path.join(Golden.directory(), "*.json"))) ==
             Enum.sort(declared)
  end

  test "the frames a client branches on carry the discriminators it branches on" do
    pruned = fixture("error_cursor_pruned")

    assert pruned["error"]["code"] == -32006
    assert pruned["error"]["data"] == %{"reason" => "cursor_pruned", "floor" => 96}

    # A ceiling breach on an `:infinity` verb admits it does not know the outcome. A client
    # that treats -32005 as "it did not happen" would be wrong, and this is what tells it.
    assert fixture("error_upstream_timeout_unknown")["error"]["data"] == %{
             "outcome" => "unknown"
           }

    lagged = fixture("stream_lagged_notification")
    refute Map.has_key?(lagged, "id")
    assert lagged["params"]["dropped"] == 128
    assert lagged["params"]["last_sequence"] == 512

    # The two event notifications differ in one field name, and a client that assumed
    # `session_id` on both would silently drop every coding event.
    assert fixture("interactive_event_notification")["params"]["event"]["session_id"]
    assert fixture("coding_event_notification")["params"]["event"]["task_id"]

    # A struct is self-describing on the wire; that tag is what lets a generic tree widget
    # label a payload it has never seen before.
    assert fixture("interactive_event_notification")["params"]["event"]["_struct"] ==
             "Ouroboros.Interactive.Event"
  end

  test "an excerpted leaf names itself and its true size, and spares the envelope" do
    payload = fixture("interactive_event_excerpt_notification")["params"]["event"]["payload"]

    # The marker a client has to learn: what arrived, and how much did not.
    assert payload["diff"] == %{
             "_excerpt" => String.duplicate("a", 48),
             "_bytes" => 600
           }

    # Cut where a three-byte character straddles the cap. 46 bytes, not 48, because a
    # client decoding this frame is owed valid UTF-8 rather than a dangling lead byte.
    assert payload["note"]["_excerpt"] == "x" <> String.duplicate("☃", 15)
    assert payload["note"]["_bytes"] == 601

    # Below the never-excerpt floor, so the marker that would have replaced it — and cost
    # more than it — never appears.
    assert payload["path"] == "lib/ouroboros/gateway/wire.ex"

    # Past the per-event budget. The size is the only thing left that is true about it.
    assert payload["tail"] == %{"_excerpt" => "", "_bytes" => 700}

    event = fixture("interactive_event_excerpt_notification")["params"]["event"]

    assert event["sequence"] == 43
    assert event["type"] == "file_change"
    assert event["timestamp"] == "2026-01-01T00:00:00.000000Z"
    assert event["session_id"] == "session-0000000000000000000001"
  end

  test "event_detail answers one bare event, whole, where the notification excerpted" do
    detail = fixture("interactive_event_detail_result")["result"]

    # Not an array and not wrapped: `replay` is the method that answers with a list, and a
    # client that unwrapped this one the same way would find no event at all.
    assert detail["_struct"] == "Ouroboros.Interactive.Event"
    assert detail["sequence"] == 43

    # The same event as the excerpt fixture, at the raised cap — which is the entire
    # reason the method exists.
    assert detail["payload"]["diff"] == String.duplicate("a", 600)
    assert detail["payload"]["tail"] == String.duplicate("z", 700)

    coding = fixture("coding_event_detail_result")["result"]

    assert coding["_struct"] == "Ouroboros.Coding.Event"
    assert coding["task_id"]
    assert coding["payload"]["diff"] == String.duplicate("b", 600)
  end

  test "the two detail methods are advertised, so a client can feature-detect them" do
    methods = fixture("hello_result")["result"]["methods"]

    assert "interactive.event_detail" in methods
    assert "coding.event_detail" in methods
  end

  test "the hello fixture lists exactly the methods this build serves" do
    assert fixture("hello_result")["result"]["methods"] == Ouroboros.Gateway.Methods.names()
  end

  test "the status fixture keeps pids per-leaf rather than opaquing the tree" do
    status = fixture("runtime_status_result")["result"]

    assert [agent] = status["agents"]
    assert agent["pid"] == %{"_opaque" => "#PID<0.123.0>"}
    assert agent["id"] == "reviewer-1"

    assert status["availability"]["control"] == "disabled"
    assert status["availability"]["mesh"] == "available"
    assert status["forge"]["signer"] == "deny"
    assert status["forge"]["admit_possible?"] == false
    assert status["forge"]["live_count"] == 0
    assert status["forge"]["live"] == []
  end

  defp fixture(name), do: name |> Golden.path() |> File.read!() |> JSON.decode!()
end
