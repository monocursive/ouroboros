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

  describe "the reply, bounded and marked (F12)" do
    test "a reply past the bound comes back as a marked string, not a cut document" do
      # M29/M37/G3. Three bytes per character, so a cut at a byte boundary lands inside one
      # unless it is walked back; and the marker is what tells a client that the JSON it is
      # holding is a prefix rather than a document.
      id = worker(%{last_answer: String.duplicate("€", 40 * 1024)})

      assert {:ok, %{truncated: true, reply: reply}} =
               Methods.invoke("agents.message", %{"to" => id, "body" => %{}})

      assert is_binary(reply)
      assert String.valid?(reply), "the cut landed inside a character"
      assert byte_size(reply) <= 64 * 1024
      assert reply =~ "truncated at 65536 bytes"
    end

    test "a reply inside the bound comes back whole, and says it was not cut" do
      id = worker(%{last_answer: %{"findings" => [], "checked" => 12}})

      assert {:ok, %{truncated: false, reply: reply}} =
               Methods.invoke("agents.message", %{"to" => id, "body" => %{}})

      assert reply == %{"findings" => [], "checked" => 12}
    end
  end

  describe "agents.state is a read of somebody else's words (F4)" do
    test "a lane-W agent's state is labelled untrusted and bounded" do
      id = "wasm/gw-#{System.unique_integer([:positive])}"
      big = String.duplicate("€", 40 * 1024)

      {:ok, _pid} =
        Mesh.start_agent(id,
          agent: Ouroboros.Agent.Worker,
          initial_state: %{last_answer: big}
        )

      on_exit(fn -> Mesh.stop_agent(id) end)

      assert {:ok, result} = Methods.invoke("agents.state", %{"id" => id})

      # `agents.state` is `:read` and it hands back the same two fields `agents.message`
      # labels. It carries the same label now, and the same bound.
      assert result.untrusted == true
      assert result.truncated == true

      answer = result.agent.state.last_answer
      assert is_binary(answer)
      assert byte_size(answer) <= 64 * 1024
      assert String.valid?(answer)
      assert answer =~ "truncated at 65536 bytes"
    end

    test "the message a capability was sent is bounded on the same rule" do
      id = "wasm/gw-#{System.unique_integer([:positive])}"

      # Seeded rather than sent, because `agents.message` caps a body at the same 64 KiB and
      # the claim here is about what `agents.state` does with a field it finds — a capability
      # is also messaged by probes, evaluations and other agents, none of which pass through
      # that cap.
      {:ok, _pid} =
        Mesh.start_agent(id,
          agent: Ouroboros.Agent.Worker,
          initial_state: %{last_message: %{body: String.duplicate("€", 40 * 1024)}}
        )

      on_exit(fn -> Mesh.stop_agent(id) end)

      assert {:ok, result} = Methods.invoke("agents.state", %{"id" => id})
      assert result.truncated == true

      message = result.agent.state.last_message
      assert is_binary(message)
      assert byte_size(message) <= 64 * 1024
      assert message =~ "truncated at 65536 bytes"
    end

    test "an agent that is not a capability is answered exactly as before" do
      id = start_worker()

      assert {:ok, result} = Methods.invoke("agents.state", %{"id" => id})

      # This is a statement about who wrote the content, not a cap on introspection.
      refute Map.has_key?(result, :untrusted)
      refute Map.has_key?(result, :truncated)
      assert is_map(result.agent.state)
    end
  end

  describe "what a message may leave behind (F9)" do
    test "an agent's inbox keeps the newest messages and drops the rest" do
      id = start_worker()
      blob = String.duplicate("x", 60 * 1024)

      # G2. `agents.message` makes an unbounded list reachable from any `:operate` client on
      # any node in the cluster: twelve of these retained three quarters of a megabyte, and
      # nothing pruned it ever. Twenty is past the byte bound, which is the one that fires
      # first for bodies this size.
      for n <- 1..20 do
        assert {:ok, %{to: ^id}} =
                 Methods.invoke("agents.message", %{
                   "to" => id,
                   "body" => %{"n" => n, "blob" => blob},
                   "timeout_ms" => 5_000
                 })
      end

      assert {:ok, %{agent: %{state: state}}} = Mesh.state(id)

      # The count is still true — a bounded mailbox is not a bounded history.
      assert state.messages_received == 20

      assert :erlang.external_size(state.inbox) <= 1024 * 1024,
             "the inbox retained #{:erlang.external_size(state.inbox)} bytes"

      # Newest kept, oldest dropped: what a mailbox is for.
      assert List.last(state.inbox).body["n"] == 20
      assert length(state.inbox) < 20
    end

    test "small messages are kept up to the count bound, and the newest survive" do
      id = start_worker()

      for n <- 1..70 do
        assert {:ok, _sent} =
                 Methods.invoke("agents.message", %{"to" => id, "body" => %{"n" => n}})
      end

      assert {:ok, %{agent: %{state: state}}} = Mesh.state(id)

      assert length(state.inbox) == 64
      assert List.last(state.inbox).body["n"] == 70
      assert List.first(state.inbox).body["n"] == 7
      assert state.messages_received == 70
    end
  end

  defp start_worker, do: worker(%{})

  defp worker(state) do
    id = "gateway-agents-message-#{System.unique_integer([:positive])}"

    {:ok, _pid} = Mesh.start_agent(id, agent: Ouroboros.Agent.Worker, initial_state: state)
    on_exit(fn -> Mesh.stop_agent(id) end)

    id
  end
end
