defmodule UkaiFleet.ClientTest do
  use ExUnit.Case, async: false
  alias UkaiFleet.{Client, Protocol}

  # Stands in for the controller process behind `UkaiFleet.Controller.call/1`.
  defmodule StubController do
    use GenServer

    def start_link(version),
      do: GenServer.start_link(__MODULE__, version, name: UkaiFleet.Controller)

    def init(version), do: {:ok, %{version: version, seen: []}}

    def handle_call({:call, :version, _deadline}, _, state),
      do: {:reply, {:ok, state.version}, state}

    def handle_call({:call, message, _deadline}, _, state),
      do: {:reply, {:ok, "ran"}, %{state | seen: [message | state.seen]}}
  end

  test "a compatible controller runs the operation; extra version fields are allowed" do
    stub = start_supervised!({StubController, Map.put(Protocol.version(), "build", "x")})
    assert {:ok, "ran"} = Client.call(node(), :doctor)
    assert :sys.get_state(stub).seen == [:doctor]
  end

  test "a protocol mismatch is reported as such and never sends the operation" do
    stub = start_supervised!({StubController, Map.put(Protocol.version(), "schema", "other/2")})
    assert {:error, "controller_schema_mismatch"} = Client.call(node(), {:run, %{}})
    assert :sys.get_state(stub).seen == []
  end

  test "an unreachable controller leaves the outcome unknown and asks for the same retry" do
    assert {:error, "controller_unreachable_or_reply_lost_retry_same_request"} =
             Client.call(:"ukai-missing@127.0.0.1", :doctor)
  end
end
