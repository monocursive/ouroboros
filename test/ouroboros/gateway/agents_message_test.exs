defmodule Ouroboros.Gateway.AgentsMessageTest do
  # Not async: every agent here joins the node-wide `:pg` mesh namespace.
  use ExUnit.Case, async: false

  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Mesh

  @moduletag :capture_log

  describe "the table (W13)" do
    test "`agents.message` is `:operate`, because it runs whatever the agent is" do
      assert "agents.message" in Methods.names()

      assert {:ok, entry} = Methods.fetch("agents.message")
      assert entry.scope == :operate

      # The claim a `:read` listener makes is that it changes nothing. Sending a message
      # into a lane-W capability *starts the containment helper* and runs a component, which
      # is the exact thing `wasm.status` and `wasm.list` are `:read` because they never do.
      refute Methods.permits?(:read, entry)
      assert Methods.permits?(:operate, entry)
    end

    test "its ceiling sits above the timeout a caller may ask for" do
      assert {:ok, %{timeout: ceiling}} = Methods.fetch("agents.message")

      assert {:error, _code, message} =
               Methods.invoke("agents.message", %{
                 "to" => "anyone",
                 "body" => %{},
                 "timeout_ms" => ceiling
               })

      # The cap is what refuses it, not the gateway ceiling: a client that asked for longer
      # than this node will wait is told so, rather than being cut off mid-wait with no way
      # to tell a slow agent from a wedged one.
      assert message =~ "timeout_ms"
    end
  end

  describe "parameters, settled before the mesh is touched" do
    test "the envelope is closed: an unknown key is refused by name" do
      assert {:error, code, message} =
               Methods.invoke("agents.message", %{
                 "to" => "someone",
                 "body" => %{},
                 "node" => "ouroboros@elsewhere"
               })

      assert code == Methods.code(:invalid_params)
      assert message =~ "node"
    end

    test "`to` is required and bounded" do
      assert {:error, _code, missing} = Methods.invoke("agents.message", %{"body" => %{}})
      assert missing =~ "params.to"

      long = String.duplicate("a", 513)

      assert {:error, _code, oversize} =
               Methods.invoke("agents.message", %{"to" => long, "body" => %{}})

      assert oversize =~ "512 bytes"
    end

    test "`body` is required, and is bounded by what it encodes to" do
      assert {:error, _code, missing} = Methods.invoke("agents.message", %{"to" => "someone"})
      assert missing =~ "params.body"

      # 64 KiB is the bound; this is one string past it, and it is refused *before* the
      # directory is consulted — a body this node will not carry must not first become a
      # lookup of whatever agent id came with it.
      big = %{"blob" => String.duplicate("x", 65 * 1024)}

      assert {:error, code, oversize} =
               Methods.invoke("agents.message", %{"to" => "someone", "body" => big})

      assert code == Methods.code(:invalid_params)
      assert oversize =~ "65536"
    end

    test "`timeout_ms` is capped, and a non-integer is refused rather than coerced" do
      for bad <- [0, 30_001, "5000", 1.5] do
        assert {:error, _code, message} =
                 Methods.invoke("agents.message", %{
                   "to" => "someone",
                   "body" => %{},
                   "timeout_ms" => bad
                 })

        assert message =~ "timeout_ms", "#{inspect(bad)} was not refused"
      end

      # The boundary itself is accepted; it fails later, on the lookup, which is the proof
      # that the cap did not reject it.
      assert {:error, code, _message} =
               Methods.invoke("agents.message", %{
                 "to" => "nobody-#{System.unique_integer([:positive])}",
                 "body" => %{},
                 "timeout_ms" => 30_000
               })

      assert code == Methods.code(:not_found)
    end
  end

  describe "delivery" do
    test "a missing agent is the mesh's own `agent_not_found`, as a not-found error" do
      id = "gateway-agents-message-absent-#{System.unique_integer([:positive])}"

      assert {:error, code, message} =
               Methods.invoke("agents.message", %{"to" => id, "body" => %{"hello" => "world"}})

      assert code == Methods.code(:not_found)
      assert message =~ id
    end

    test "a message reaches an agent, and the reply comes back labelled untrusted" do
      id = start_worker()

      assert {:ok, result} =
               Methods.invoke("agents.message", %{
                 "to" => id,
                 "body" => %{"question" => "what"},
                 "from" => "operator"
               })

      assert result.to == id
      assert result.from == "operator"

      # Both flags are always present. `untrusted` because a reply is authored by whatever
      # the agent is — for lane W, by a component — and `truncated` because a client holding
      # a cut JSON document has to be able to tell that is what it is holding.
      assert result.untrusted == true
      assert result.truncated == false

      # The agent recorded the message it was handed, which is the evidence it arrived
      # rather than being answered from somewhere on the way.
      assert {:ok, %{agent: %{state: state}}} = Mesh.state(id)
      assert state.last_message.body == %{"question" => "what"}
      assert state.last_message.from == "operator"
    end

    test "an absent `from` says `gateway` rather than inventing an identity" do
      id = start_worker()

      assert {:ok, result} = Methods.invoke("agents.message", %{"to" => id, "body" => %{}})
      assert result.from == "gateway"
    end
  end

  defp start_worker do
    id = "gateway-agents-message-#{System.unique_integer([:positive])}"

    {:ok, _pid} = Mesh.start_agent(id, agent: Ouroboros.Agent.Worker)
    on_exit(fn -> Mesh.stop_agent(id) end)

    id
  end
end
