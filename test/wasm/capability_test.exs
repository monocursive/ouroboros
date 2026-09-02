defmodule Ouroboros.Wasm.CapabilityTest do
  # Not async: every agent here joins the node-wide `:pg` mesh namespace, and each test
  # spawns a real OS child as its helper.
  use ExUnit.Case, async: false

  alias Ouroboros.Mesh
  alias Ouroboros.Upgrade.Rollout.Evaluation
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.Capability
  alias Ouroboros.Wasm.Pool
  alias Ouroboros.Wasm.Store

  # A helper whose `worlds` does not include this node's is refused at the handshake, so the
  # fixture has to speak the real one.
  @doctor ~S(\"usable\":true,\"worlds\":[\"ouroboros:capability@0.1.0\"],) <>
            ~S(\"wasmtime\":\"48.0.1\",\"limits\":{\"max_deadline_ms\":60000})

  # The helper here is a shell script, exactly as it is in `Ouroboros.Wasm.PoolTest`: this
  # slice's subject is the wrapper agent's decisions — when it loads, when it instantiates,
  # what it does with each named refusal — and a scripted helper is the only way to put a
  # `trapped` and a `guest_error` next to each other in one file. The real wire is
  # `test/wasm/capability_acceptance_test.exs`, against a real component.

  describe "lazy: the first message is what loads and instantiates" do
    test "load, instantiate, call — in that order, once" do
      %{id: id, journal: journal} =
        capability(call: [result(%{"payload" => ~s({"echo":"one","n":1}), "fuel_used" => 42})])

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{op: "ping"})

      state = state(id)

      # `:last_message` is the shape `Ouroboros.Agent.Worker.ReceiveMessage` writes, which is
      # what makes `Rollout.Probe`'s echo check work against a wasm capability unchanged.
      assert state.last_message == %{
               from: "tester",
               body: %{op: "ping"},
               correlation_id: state.last_message.correlation_id,
               causation_id: nil
             }

      # The reply is JSON, so it is the term it encodes — with string keys, because nothing
      # a guest sent is ever turned into an atom.
      assert state.last_answer == %{"echo" => "one", "n" => 1}
      assert state.messages_received == 1
      assert state.error == nil
      assert is_binary(state.instance)

      assert methods(journal) == ["doctor", "load", "instantiate", "call"]

      # The component is named by its sha and by nothing else, and the bounds are the
      # configured defaults, sent explicitly.
      assert %{"params" => %{"sha256" => sha, "limits" => limits}} =
               request(journal, "instantiate")

      assert sha == state.component

      assert limits == %{
               "fuel" => Wasm.capability_limits().fuel,
               "memory_bytes" => Wasm.capability_limits().memory_bytes,
               "deadline_ms" => Wasm.capability_limits().deadline_ms
             }

      # The body crosses as JSON, and the export is the world's.
      assert %{"params" => %{"export" => "handle-message", "payload" => payload}} =
               request(journal, "call")

      assert JSON.decode!(payload) == %{"op" => "ping"}
    end

    test "nothing is loaded and nothing is instantiated until a message arrives" do
      %{id: id, journal: journal} = capability([])

      assert state(id).instance == nil
      assert File.read!(journal) == ""
    end

    test "a second message reuses the instance the first one stood up" do
      %{id: id, journal: journal} =
        capability(
          call: [
            result(%{"payload" => ~s({"n":1}), "fuel_used" => 1}),
            result(%{"payload" => ~s({"n":2}), "fuel_used" => 1})
          ]
        )

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 1})
      first = state(id).instance

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 2})
      state = state(id)

      assert state.instance == first
      assert state.last_answer == %{"n" => 2}
      assert state.messages_received == 2

      # One instantiate for two messages. That is the whole reason guest state is observable
      # across messages at all.
      assert Enum.count(methods(journal), &(&1 == "instantiate")) == 1
      assert Enum.count(methods(journal), &(&1 == "call")) == 2

      # And the instance name is derived from the agent id, not minted per message and not
      # built out of the free-form `:name`.
      assert first == derived_name(id)
      refute first =~ "greeter"
    end
  end

  describe "an instance belongs to the agent whose id derived it (F1)" do
    test "a seeded instance naming somebody else's is ignored, not adopted" do
      # `Mesh.start_agent/2` is remote-reachable and merges the caller's `initial_state`
      # wholesale — Jido does not validate it against the schema — so a thief can ask to be
      # started holding the victim's instance name. Believing it handed the thief the
      # victim's live guest, its config, and its accumulated state.
      %{id: victim} =
        env = capability(call: [result(%{"payload" => ~s({"n":1}), "fuel_used" => 1})])

      assert {:ok, _agent} = Mesh.send_message("tester", victim, %{seq: 1})
      stolen = state(victim).instance
      assert stolen == derived_name(victim)

      %{id: thief} = capability([], env: env, instance: stolen)

      assert {:ok, _agent} = Mesh.send_message("tester", thief, %{seq: 1})

      # The thief got its own instance, under its own derived name, and had to stand it up.
      assert state(thief).instance == derived_name(thief)
      assert state(thief).instance != stolen

      calls =
        env.journal
        |> requests()
        |> Enum.filter(&(&1["method"] == "call"))
        |> Enum.map(& &1["params"]["instance"])

      assert calls == [stolen, derived_name(thief)]

      # Two instantiates: the thief was never allowed to ride the victim's.
      assert Enum.count(methods(env.journal), &(&1 == "instantiate")) == 2

      # And the victim still holds the instance it stood up.
      assert state(victim).instance == stolen
    end

    test "a seeded instance equal to this agent's own derived name is honored" do
      # The other half of the rule: the derived name depends only on the agent's own id, so
      # an agent seeded with its own name is claiming nothing that was not already its own.
      id = "wasm-self-seeded-#{System.unique_integer([:positive])}"

      %{journal: journal} =
        capability([call: [result(%{"payload" => ~s({"n":9}), "fuel_used" => 1})]],
          id: id,
          instance: derived_name(id)
        )

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 1})

      assert state(id).last_answer == %{"n" => 9}
      assert methods(journal) == ["doctor", "call"]
    end
  end

  describe "instance names are injective (F2)" do
    test "the (name, id) pairs that used to collide get different instances" do
      # `\"\#{name}/\#{id}\"` made these two the same string, so whichever agent started
      # second reclaimed the first one's instance through `instance_exists` recovery and
      # then answered its messages from the wrong component.
      env = capability(call: [result(%{"payload" => "{}", "fuel_used" => 1})])

      %{id: left} = capability([], env: env, id: "n-mid-tail-#{unique()}-tail", name: "n/mid")
      %{id: right} = capability([], env: env, id: "n-mid-tail-#{unique()}-mid/tail", name: "n")

      assert {:ok, _agent} = Mesh.send_message("tester", left, %{seq: 1})
      assert {:ok, _agent} = Mesh.send_message("tester", right, %{seq: 1})

      assert state(left).instance != state(right).instance
      assert state(left).instance == derived_name(left)
      assert state(right).instance == derived_name(right)
    end

    test "an id that looks like the hashed form cannot reach the hashed form" do
      # The over-cap branch used to be `\"wasm/\" <> sha256hex`, which `name: \"wasm\"` plus a
      # 64-hex id reproduced exactly. url-safe base64 contains no `/`, so an encoded name has
      # one slash and a hashed one has two: the two forms are disjoint by construction.
      hex = String.duplicate("a", 64)
      %{id: id} = capability([], id: hex, name: "wasm")

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 1})

      instance = state(id).instance
      assert instance == derived_name(hex)
      refute String.starts_with?(instance, "wasm/h/")
      refute instance =~ hex
    end

    test "an id too long to encode is hashed, and stays inside the pool's bound" do
      long = String.duplicate("i", 400)
      %{id: id, journal: journal} = capability([], id: long)

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 1})

      instance = state(id).instance
      assert String.starts_with?(instance, "wasm/h/")
      assert byte_size(instance) <= 256

      # The pool refuses a longer name than the helper will echo, so an unbounded id would
      # have made this agent unable to stand anything up at all.
      assert %{"params" => %{"instance" => ^instance}} = request(journal, "instantiate")
    end

    test "two agents on one pool hold two instances, and neither sees the other's" do
      # The blind spot the theft and the collision both lived in: nothing asserted that two
      # agents get *different* instances.
      env =
        capability(
          call: [
            result(%{"payload" => ~s({"who":"first"}), "fuel_used" => 1}),
            result(%{"payload" => ~s({"who":"second"}), "fuel_used" => 1})
          ]
        )

      %{id: first} = capability([], env: env)
      %{id: second} = capability([], env: env)

      assert {:ok, _agent} = Mesh.send_message("tester", first, %{seq: 1})
      assert {:ok, _agent} = Mesh.send_message("tester", second, %{seq: 1})

      assert state(first).instance == derived_name(first)
      assert state(second).instance == derived_name(second)
      assert state(first).instance != state(second).instance

      assert state(first).last_answer == %{"who" => "first"}
      assert state(second).last_answer == %{"who" => "second"}

      instantiated =
        env.journal
        |> requests()
        |> Enum.filter(&(&1["method"] == "instantiate"))
        |> Enum.map(& &1["params"]["instance"])

      assert instantiated == [derived_name(first), derived_name(second)]
      refute "drop" in methods(env.journal)
    end
  end

  describe "a refusal that poisons the instance" do
    test "a trap clears the instance, and the next message stands a fresh one up" do
      %{id: id, journal: journal} =
        capability(
          call: [
            result(%{"payload" => ~s({"n":1}), "fuel_used" => 1}),
            refusal(-32_014, "trapped", "guest trapped in handle-message"),
            result(%{"payload" => ~s({"n":1}), "fuel_used" => 1})
          ]
        )

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 1})
      standing = state(id).instance
      assert is_binary(standing)

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 2})
      trapped = state(id)

      # Cleared, recorded — and the agent is still here, which is the point: a hostile guest
      # must not be able to take down the process containing it.
      assert trapped.instance == nil
      assert trapped.last_answer == nil
      assert %{stage: :call, reason: %{refusal: "trapped", code: -32_014}} = trapped.error
      assert trapped.messages_received == 2
      assert is_pid(Mesh.whereis(id))

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 3})
      recovered = state(id)

      assert recovered.instance == standing
      assert recovered.last_answer == %{"n" => 1}
      assert recovered.error == nil

      # A trap frees the name helper-side, so the recovery is a second instantiate under the
      # same name — no drop, and no name invented to work around a stranded one.
      assert Enum.count(methods(journal), &(&1 == "instantiate")) == 2
      refute "drop" in methods(journal)
    end

    test "every poisoning refusal clears the instance, and no other one does" do
      for {code, name} <- [
            {-32_011, "fuel_exhausted"},
            {-32_012, "deadline_exceeded"},
            {-32_013, "memory_limit"},
            {-32_007, "unknown_instance"}
          ] do
        %{id: id} =
          capability(
            call: [
              result(%{"payload" => ~s({"n":1}), "fuel_used" => 1}),
              refusal(code, name, "bounded")
            ]
          )

        assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 1})
        assert is_binary(state(id).instance)

        assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 2})
        assert state(id).instance == nil, "#{name} did not clear the instance"
        assert %{stage: :call, reason: %{refusal: ^name}} = state(id).error
      end
    end

    test "a refusal that is not about the instance keeps it" do
      %{id: id} =
        capability(
          call: [
            result(%{"payload" => ~s({"n":1}), "fuel_used" => 1}),
            refusal(-32_016, "oversize_result", "`handle-message` returned too many bytes")
          ]
        )

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 1})
      standing = state(id).instance

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 2})
      state = state(id)

      assert state.instance == standing
      assert state.last_answer == nil
      assert %{stage: :call, reason: %{refusal: "oversize_result"}} = state.error
    end
  end

  describe "a guest that answers badly is still a guest that answered" do
    test "guest_error is recorded and the instance is kept" do
      %{id: id, journal: journal} =
        capability(
          call: [
            refusal(-32_017, "guest_error", "body is not JSON: expected value"),
            result(%{"payload" => ~s({"n":2}), "fuel_used" => 1})
          ]
        )

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 1})
      refused = state(id)

      # The guest's own `err` payload is what it said, so it is what `:last_answer` holds.
      assert refused.last_answer == "body is not JSON: expected value"
      assert %{stage: :call, reason: %{refusal: "guest_error"}} = refused.error
      assert is_binary(refused.instance)

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 2})
      assert state(id).last_answer == %{"n" => 2}
      assert state(id).error == nil

      assert Enum.count(methods(journal), &(&1 == "instantiate")) == 1
    end

    test "a reply that is not JSON stays the string it was" do
      %{id: id} = capability(call: [result(%{"payload" => "plain prose", "fuel_used" => 1})])

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 1})
      assert state(id).last_answer == "plain prose"
      assert state(id).error == nil
    end
  end

  describe "nothing takes the agent down" do
    test "a component the store does not hold is an error, and the helper is never asked" do
      %{id: id, journal: journal} =
        capability([], component: String.duplicate("b", 64))

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 1})
      state = state(id)

      assert %{stage: :store, reason: {:unknown_component, _sha}} = state.error
      assert state.instance == nil
      assert state.last_answer == nil

      # `:last_message` is still the message it received, so `Probe`'s echo check is about
      # the agent rather than about whether this node has a component on disk.
      assert state.last_message.body == %{seq: 1}
      assert state.messages_received == 1
      assert is_pid(Mesh.whereis(id))
      assert File.read!(journal) == ""
    end

    test "a node that never built a helper is :unavailable, not a crash" do
      %{id: id} = capability([], helper: :absent)

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 1})
      state = state(id)

      assert state.error == %{stage: :load, reason: :unavailable}
      assert state.instance == nil
      assert state.last_message.body == %{seq: 1}
      assert is_pid(Mesh.whereis(id))
    end

    test "a helper that breaks its own result contract is recorded by shape, not content" do
      %{id: id} = capability(call: [result(%{"surprise" => "not a payload"})])

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 1})

      assert %{stage: :call, reason: {:malformed_result, ["surprise"]}} = state(id).error
      assert is_pid(Mesh.whereis(id))
    end

    test "an exception anywhere in the exchange still records the message (F4)" do
      # `Mesh.start_agent/2` does not validate `initial_state` against this schema, so a
      # component that is not a string reaches `Store.path/2`'s `is_binary` guard, and a pool
      # that is not a server reaches `GenServer.whereis/1`'s — which the pool's own
      # `catch :exit` does not catch. Both used to lose the entire state write while
      # `Mesh.send_message/4` still answered `{:ok, agent}`.
      for {label, opts} <- [
            {"a component that is not a sha", [component: 123]}
          ] do
        %{id: id} = capability([], opts)

        assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 1})
        state = state(id)

        assert %{stage: :exception, reason: reason} = state.error, label
        assert is_binary(reason), label

        # The point of the fix: the bookkeeping happens whatever the exchange did.
        assert state.messages_received == 1, label
        assert state.last_message.body == %{seq: 1}, label
        assert state.instance == nil, label
        assert is_pid(Mesh.whereis(id)), label
      end
    end

    test "a recorded refusal is bounded however large the term that produced it is (F6)" do
      # The original shape of this — a `call` against a pool that is not running, whose exit
      # reason carries the whole outbound payload — is no longer reachable: a `:pool` that
      # does not resolve to a live local `Ouroboros.Wasm.Pool` is refused before a request is
      # built (F3), and the test below proves that. What is still reachable, and is the same
      # bound, is a refusal built out of a caller-supplied *term*: `Store.path/2` answers
      # `{:invalid_sha256, sha}` with the whole of what it was handed.
      huge = String.duplicate("component-", 20_000)
      secret = String.duplicate("payload-", 20_000)
      %{id: id} = capability([], component: huge)

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{"body" => secret})

      assert %{stage: :store, reason: reason} = state(id).error
      assert is_binary(reason)

      # Cut, rather than the 200 KB term the store handed back.
      assert byte_size(reason) <= 2_048 + 8
      assert byte_size(huge) > 100_000
      refute reason =~ String.duplicate("component-", 100)

      # And never the message that produced it, which is what a `GenServer.call/3` exit
      # reason carries whole.
      refute reason =~ "payload-"
    end

    test "a malformed frame's keys are bounded by bytes, not only counted (F6)" do
      wide =
        1..12
        |> Map.new(fn n -> {String.duplicate("k#{n}", 500), n} end)

      %{id: id} = capability(call: [result(wide)])

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 1})

      assert %{stage: :call, reason: {:malformed_result, keys}} = state(id).error
      assert length(keys) == 8
      assert Enum.all?(keys, &(byte_size(&1) <= 128 + byte_size("…")))
      assert :erlang.external_size(state(id).error) <= 2_048
    end

    test "a helper that is gone clears the instance rather than wasting a message (F7)" do
      # `:broken` means the pool already hard-closed and killed the child, so the helper's
      # table went with it; keeping `:instance` spent the next message discovering
      # `unknown_instance`, which scores a probe failure against a healthy capability.
      %{id: id} =
        capability(
          call: [
            result(%{"payload" => ~s({"n":1}), "fuel_used" => 1}),
            ~s|outcome {"who":"knows"}|
          ]
        )

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 1})
      assert is_binary(state(id).instance)

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 2})
      assert state(id).error == %{stage: :call, reason: :broken}
      assert state(id).instance == nil
    end

    test "a helper that was never built clears the instance too (F7)" do
      id = "wasm-absent-helper-#{System.unique_integer([:positive])}"

      %{id: ^id} = capability([], id: id, instance: derived_name(id), helper: :absent)

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 1})

      assert state(id).error == %{stage: :call, reason: :unavailable}
      assert state(id).instance == nil
    end

    test "a body this node cannot encode is refused before the helper is touched" do
      %{id: id, journal: journal} = capability([])

      # A pid survives a local mesh call and does not survive JSON. The refusal names the
      # stage, the agent lives, and nothing was sent.
      assert {:ok, _agent} = Mesh.send_message("tester", id, %{owner: self()})

      assert %{stage: :encode, reason: {:unencodable_body, _message}} = state(id).error
      assert is_pid(Mesh.whereis(id))
      assert File.read!(journal) == ""
    end

    test "an instance stranded under this agent's name is reclaimed, not orphaned" do
      # The case Jido's missing terminate hook leaves open: a previous incarnation of this
      # agent id stopped without dropping. The name belongs to this id, so it is taken back.
      %{id: id, journal: journal} =
        capability(
          instantiate: [
            refusal(-32_008, "instance_exists", "instance is live; drop it before instantiating"),
            result(%{"instance" => "greeter", "fuel_used" => 1})
          ],
          call: [result(%{"payload" => ~s({"n":1}), "fuel_used" => 1})]
        )

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 1})

      assert state(id).last_answer == %{"n" => 1}
      assert state(id).error == nil
      assert methods(journal) == ["doctor", "load", "instantiate", "drop", "instantiate", "call"]
    end
  end

  describe "limits" do
    test "the state's own bounds are used when it names all three" do
      %{id: id, journal: journal} =
        capability([call: [result(%{"payload" => "{}", "fuel_used" => 1})]],
          limits: %{fuel: 7_000_000, memory_bytes: 1_048_576, deadline_ms: 250}
        )

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 1})

      assert %{"params" => %{"limits" => limits}} = request(journal, "instantiate")

      assert limits == %{
               "fuel" => 7_000_000,
               "memory_bytes" => 1_048_576,
               "deadline_ms" => 250
             }
    end

    test "a half-stated bound is not a bound: it falls back whole" do
      %{id: id, journal: journal} =
        capability([call: [result(%{"payload" => "{}", "fuel_used" => 1})]],
          limits: %{fuel: 7_000_000}
        )

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 1})

      assert %{"params" => %{"limits" => limits}} = request(journal, "instantiate")
      assert limits["fuel"] == Wasm.capability_limits().fuel
      refute limits["fuel"] == 7_000_000
    end

    test "an eval spec cannot seed an instance around the start spec (F5)" do
      # `Evaluation` merges a spec's `initial_state` under the start spec's, so a signed spec
      # can still seed any key the start spec leaves out — and `:instance` is one of them.
      # It is safe unnamed only because a seeded instance that is not this agent's own is
      # ignored; that is what this asserts, through the machinery that would exploit it.
      %{id: victim} =
        env = capability(call: [result(%{"payload" => ~s({"n":1}), "fuel_used" => 1})])

      assert {:ok, _agent} = Mesh.send_message("tester", victim, %{seq: 1})
      stolen = state(victim).instance

      start_spec =
        {Capability,
         %{
           component: env.sha,
           config: ~s({"greeting":"hello"}),
           name: "greeter",
           limits: %{fuel: 1_000_000, memory_bytes: 1_048_576, deadline_ms: 500},
           pool: env.pool,
           store_root: env.root
         }}

      spec = %{
        probes: [%{input: %{"seq" => 1}, expect: :any_reply}],
        initial_state: %{instance: stolen},
        budget_ms: 5_000
      }

      assert {:ok, report} = Evaluation.run(start_spec, spec)
      assert Evaluation.passed?(report)

      # The evaluation stood its own instance up rather than riding the victim's, so the
      # victim's is still the only call made against that name.
      calls =
        env.journal
        |> requests()
        |> Enum.filter(&(&1["method"] == "call"))
        |> Enum.map(& &1["params"]["instance"])

      assert [^stolen, other] = calls
      assert other != stolen
    end

    test "limits/1 is the same decision, callable without an agent" do
      assert Capability.limits(%{limits: %{fuel: 1, memory_bytes: 2, deadline_ms: 3}}) ==
               %{fuel: 1, memory_bytes: 2, deadline_ms: 3}

      assert Capability.limits(%{limits: %{}}) == Wasm.capability_limits()

      assert Capability.limits(%{limits: %{fuel: 0, memory_bytes: 2, deadline_ms: 3}}) ==
               Wasm.capability_limits()
    end
  end

  describe "nothing in initial_state is trusted, because nothing validates it (F3)" do
    test "a malformed seeded message counter cannot bypass bookkeeping" do
      %{id: id} =
        capability([call: [result(%{"payload" => ~s({"n":1}), "fuel_used" => 1})]],
          messages_received: "not-a-counter"
        )

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 1})

      state = state(id)
      assert state.messages_received == 1
      assert state.last_message.body == %{seq: 1}
      assert state.last_answer == %{"n" => 1}
    end

    test "a pool that is not this node's wasm pool is refused, and no request is sent" do
      # The proof the review ran: `pool: [type: :any]` let a remote starter aim this agent's
      # `GenServer.call` at any registered process, and the pool's `{:request, …}` tuple then
      # killed the process that received it on a `function_clause`. Here the victim is a
      # plain `Agent` under a name the starter chose, and it has to survive the message.
      victim_name = :"wasm_capability_victim_#{unique()}"
      {:ok, victim} = Agent.start(fn -> :untouched end, name: victim_name)
      on_exit(fn -> if Process.alive?(victim), do: Agent.stop(victim) end)

      for {label, aimed} <- [
            {"a registered name", victim_name},
            {"a bare pid", victim},
            {"a string", "not-a-server"},
            {"a module that is not the pool", Ouroboros.Wasm.Store}
          ] do
        %{id: id} = capability([], pool: aimed)

        assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 1})
        state = state(id)

        assert %{stage: :pool, reason: {:pool_not_a_wasm_pool, described}} = state.error, label
        assert is_binary(described), label

        # Recorded, answered, and the agent is still an agent that received a message.
        assert state.messages_received == 1, label
        assert state.instance == nil, label
        assert is_pid(Mesh.whereis(id)), label
      end

      # The whole point: nothing was ever sent, so the process somebody aimed at is alive
      # and holds exactly what it held.
      assert Process.alive?(victim)
      assert Agent.get(victim, & &1) == :untouched
    end

    test "the node's own pool is always allowed, running or not" do
      # `Ouroboros.Wasm.Pool` is this node's lazy singleton and is not refused as a start
      # state: a node where it is not running answers `:unavailable` through the ordinary
      # path, which is a more honest sentence than "you may not name your own pool".
      %{id: id} = capability([], pool: Ouroboros.Wasm.Pool, component: "not-a-sha")

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 1})

      # It got past the pool check and refused on the component instead.
      assert %{stage: :store} = state(id).error
    end

    test "a seeded store_root is ignored where config does not allow the override" do
      # `:store_root` names which bytes run. On a remote-reachable start surface that is an
      # arbitrary read of unsigned, unregistered bytes out of any directory this user can
      # read, so it is honoured only where the node's own config says so.
      env = capability(load: [result(%{"cached" => false, "evicted" => []})])

      put_wasm_config(allow_store_root_override: false)

      %{id: id} = capability([], env: env, id: "wasm-root-#{unique()}")

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 1})

      # The seeded root held the only copy of these bytes, and the node's own store is not
      # the seeded directory — so the component was never found, never loaded, and never
      # instantiated. (This node configures no `:data_dir`, so its own store root is
      # `:no_data_dir`; a node that has one answers `{:unknown_component, sha}`. Either way
      # the seeded directory was not read.)
      assert %{stage: :store, reason: reason} = state(id).error
      assert reason in [:no_data_dir] or match?({:unknown_component, _sha}, reason)
      refute Enum.any?(requests(env.journal), &(&1["method"] == "load"))
    end

    test "declared limits are clamped to the node's ceiling, and the clamp is recorded" do
      # Proved on the wire before this: a remote starter wrote the helper's own maxima into
      # `initial_state` and got them — a trillion units of fuel, a gibibyte, sixty seconds
      # per message — on a node that had agreed to none of it.
      ceiling = Wasm.capability_limits_max()
      greedy = %{fuel: 1_000_000_000_000, memory_bytes: 1_073_741_824, deadline_ms: 60_000}

      %{id: id, journal: journal} =
        capability([call: [result(%{"payload" => ~s({"n":1}), "fuel_used" => 1})]],
          limits: greedy
        )

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 1})

      # What went out is the ceiling, element-wise, not what was declared.
      assert %{"params" => %{"limits" => sent}} = request(journal, "instantiate")

      assert sent == %{
               "fuel" => ceiling.fuel,
               "memory_bytes" => ceiling.memory_bytes,
               "deadline_ms" => ceiling.deadline_ms
             }

      # And the declaration this node would not honour is visible rather than silently
      # obeyed — on a message that otherwise succeeded.
      state = state(id)
      assert state.last_answer == %{"n" => 1}
      assert %{stage: :limits, reason: {:limits_clamped, ^greedy, clamped}} = state.error
      assert clamped == ceiling
    end

    test "a declaration inside the ceiling is honoured whole, and records nothing" do
      modest = %{fuel: 1_000_000, memory_bytes: 1_048_576, deadline_ms: 500}

      %{id: id, journal: journal} =
        capability([call: [result(%{"payload" => ~s({"n":1}), "fuel_used" => 1})]],
          limits: modest
        )

      assert {:ok, _agent} = Mesh.send_message("tester", id, %{seq: 1})

      assert %{"params" => %{"limits" => sent}} = request(journal, "instantiate")

      assert sent == %{
               "fuel" => 1_000_000,
               "memory_bytes" => 1_048_576,
               "deadline_ms" => 500
             }

      assert state(id).error == nil
      assert Capability.note(%{limits: modest}) == nil
    end

    test "limits/1 clamps whatever it is handed, defaults included" do
      ceiling = Wasm.capability_limits_max()

      assert Capability.limits(%{limits: %{fuel: 1, memory_bytes: 2, deadline_ms: 3}}) ==
               %{fuel: 1, memory_bytes: 2, deadline_ms: 3}

      assert Capability.limits(%{
               limits: %{
                 fuel: ceiling.fuel * 2,
                 memory_bytes: ceiling.memory_bytes * 2,
                 deadline_ms: ceiling.deadline_ms * 2
               }
             }) == ceiling

      # An operator who raised `capability_limits` past the ceiling raised nothing: the
      # default is clamped by the same rule as a declaration.
      put_wasm_config(
        capability_limits: [
          fuel: ceiling.fuel * 2,
          memory_bytes: ceiling.memory_bytes * 2,
          deadline_ms: ceiling.deadline_ms * 2
        ]
      )

      assert Capability.limits(%{limits: %{}}) == ceiling
    end
  end

  ## Fixtures

  # One capability agent, its own pool, its own helper, its own store. `plans` scripts the
  # helper's answers per method; anything unscripted gets a plausible default. Pass
  # `env: <a previous fixture>` to start a second agent against the same helper and store,
  # which is what the theft and collision proofs need.
  defp capability(plans, opts \\ []) do
    opts
    |> Keyword.get_lazy(:env, fn -> env(plans, opts) end)
    |> agent(opts)
  end

  # A pool, a helper, and a store holding one component.
  defp env(plans, opts) do
    dir = tmp_dir()
    root = Path.join(dir, "store")
    File.mkdir_p!(root)

    # Any bytes: the scripted helper never parses them, and the store only cares that the
    # name of a component is the digest of its content.
    {:ok, %{sha256: sha}} =
      Store.put("component bytes #{System.unique_integer()}", nil, root: root)

    journal = Path.join(dir, "journal")
    File.write!(journal, "")

    helper =
      case Keyword.get(opts, :helper) do
        :absent -> Path.join(dir, "ouro-wasm-that-was-never-built")
        _present -> write_helper(dir, journal, plans)
      end

    %{journal: journal, pool: start_pool(helper), root: root, sha: sha}
  end

  defp agent(env, opts) do
    id =
      Keyword.get_lazy(opts, :id, fn ->
        "wasm-capability-#{System.unique_integer([:positive])}"
      end)

    initial_state =
      %{
        component: Keyword.get(opts, :component, env.sha),
        config: Keyword.get(opts, :config, ~s({"greeting":"hello"})),
        name: Keyword.get(opts, :name, "greeter"),
        pool: Keyword.get(opts, :pool, env.pool),
        store_root: env.root
      }
      |> seed(opts, :limits)
      |> seed(opts, :instance)
      |> seed(opts, :messages_received)

    {:ok, _pid} = Mesh.start_agent(id, agent: Capability, initial_state: initial_state)
    on_exit(fn -> Mesh.stop_agent(id) end)

    Map.put(env, :id, id)
  end

  # Replaces a few keys of the node's shipped `:wasm` config for one test and restores the
  # whole keyword at teardown. Built from the running config rather than from a literal, so
  # a test that moves one bound does not silently rewrite the other eight. This module is
  # `async: false` precisely because this is global.
  defp put_wasm_config(overrides) do
    previous = Application.get_env(:ouroboros, :wasm, [])
    on_exit(fn -> Application.put_env(:ouroboros, :wasm, previous) end)
    Application.put_env(:ouroboros, :wasm, Keyword.merge(previous, overrides))
  end

  defp seed(state, opts, key) do
    case Keyword.fetch(opts, key) do
      {:ok, value} -> Map.put(state, key, value)
      :error -> state
    end
  end

  # The name the wrapper derives for an agent id, computed here the way the module documents
  # it rather than read back out of the module — a test that asks the subject what it did
  # cannot notice the subject changing its mind.
  defp derived_name(id), do: "wasm/" <> Base.url_encode64(id, padding: false)

  defp unique, do: System.unique_integer([:positive])

  defp state(id) do
    {:ok, server_state} = Mesh.state(id)
    server_state.agent.state
  end

  defp result(map), do: "result " <> JSON.encode!(map)

  defp refusal(code, name, message),
    do: "error " <> JSON.encode!(%{code: code, data: %{refusal: name}, message: message})

  # Every request the helper saw, in arrival order, decoded.
  defp requests(journal) do
    journal
    |> File.read!()
    |> String.split("\n", trim: true)
    |> Enum.map(&JSON.decode!/1)
  end

  defp methods(journal), do: journal |> requests() |> Enum.map(& &1["method"])

  defp request(journal, method) do
    journal |> requests() |> Enum.find(&(&1["method"] == method))
  end

  defp start_pool(helper_path) do
    name = :"wasm_capability_pool_#{System.unique_integer([:positive])}"

    {:ok, pid} =
      Pool.start(name: name, helper_path: helper_path, handshake_timeout_ms: 15_000)

    on_exit(fn ->
      if Process.alive?(pid) do
        try do
          GenServer.stop(pid, :normal, 1_000)
        catch
          :exit, _reason -> :ok
        end
      end
    end)

    pid
  end

  # A helper whose answers come out of per-method plan files, one line per request. A line is
  # `result <json>` or `error <json>`; a method with no line left answers the default below.
  # The plan paths are baked into the script rather than passed through the environment, so
  # two of these can never see each other's plans.
  defp write_helper(dir, journal, plans) do
    files =
      Map.new([:call, :instantiate, :load, :drop], fn method ->
        path = Path.join(dir, "plan-#{method}")
        File.write!(path, Enum.map_join(Keyword.get(plans, method, []), "", &(&1 <> "\n")))
        {method, path}
      end)

    body = """
    #!/bin/sh
    exec awk '
    {
      print $0 >> "#{journal}"
      close("#{journal}")
      id = $0
      sub(/.*"id":/, "", id)
      sub(/[^0-9].*/, "", id)
      method = $0
      sub(/.*"method":"/, "", method)
      sub(/".*/, "", method)
      file = ""
      if (method == "call") { file = "#{files.call}" } else if (method == "instantiate") { file = "#{files.instantiate}" } else if (method == "load") { file = "#{files.load}" } else if (method == "drop") { file = "#{files.drop}" }
      plan = ""
      if (file != "") { if ((getline plan < file) <= 0) { plan = "" } }
      if (plan != "") {
        kind = substr(plan, 1, index(plan, " ") - 1)
        rest = substr(plan, index(plan, " ") + 1)
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"%s\\":%s}\\n", id, kind, rest)
      } else if (method == "doctor") {
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{#{@doctor}}}\\n", id)
      } else if (method == "call") {
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{\\"payload\\":\\"{}\\",\\"fuel_used\\":1}}\\n", id)
      } else {
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{\\"method\\":\\"%s\\"}}\\n", id, method)
      }
      fflush()
    }
    '
    """

    path = Path.join(dir, "ouro-wasm-helper.sh")
    File.write!(path, body)
    File.chmod!(path, 0o755)
    path
  end

  # One directory per test, removed at teardown: a shared tmp name is the flake this suite
  # has been bitten by before.
  defp tmp_dir do
    dir =
      Path.join(System.tmp_dir!(), "ouro-wasm-capability-#{System.unique_integer([:positive])}")

    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)
    dir
  end
end
