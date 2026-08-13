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
  end

  defp fixture(name), do: name |> Golden.path() |> File.read!() |> JSON.decode!()
end
