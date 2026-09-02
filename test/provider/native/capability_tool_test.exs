defmodule Ouroboros.Provider.Native.CapabilityToolTest do
  @moduledoc """
  W13 — a live capability is a tool, and the seam between two untrusted parties.

  The claims here are the ones the tool is worth nothing without: only a `:live` lane-W
  rollout is reachable, a body this node will not carry never becomes a message, a reply is
  bounded and labelled, and the permission engine is asked with a name *this node*
  resolved rather than one the model wrote.

  The agents these tests message are ordinary `Ouroboros.Agent.Worker`s standing at the
  lane's ids. That is deliberate and it is not a simulation of the wrapper: the tool's
  contract with a capability is exactly `Ouroboros.Mesh`'s — a message in, `:last_answer`
  out — and using the wrapper here would have meant a helper, a store and a component in a
  test about which *names* are reachable. The wrapper against a real component is
  `test/wasm/capability_acceptance_test.exs`.
  """

  # Not async: it writes into this node's rollout register and its `:pg` mesh namespace.
  use ExUnit.Case, async: false

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Control.Permissions
  alias Ouroboros.Mesh
  alias Ouroboros.Provider.Native.Loop
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Provider.Native.Tools.Capability
  alias Ouroboros.Test.NativeModelScript
  alias Ouroboros.Upgrade.Rollout.Registry

  @moduletag :capture_log

  @sha String.duplicate("d1", 32)
  @other_sha String.duplicate("e2", 32)

  setup do
    previous = Application.get_env(:ouroboros, :permissions)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:ouroboros, :permissions, previous),
        else: Application.delete_env(:ouroboros, :permissions)
    end)

    :ok
  end

  describe "which names are reachable at all" do
    test "only `:live` lane-W entries are listed" do
      live = deploy_live("vet", @sha)
      _superseded = deploy("stale", @other_sha, :superseded)
      _lane_b = deploy_lane_b()

      names = Enum.map(Capability.live(), & &1.name)

      assert live in names
      refute "stale" in names

      # A lane-B rollout deploys a module, not a component, and has no `component_sha256`.
      # It must never appear here: this tool's whole gate is "a live component", and a
      # register entry that is not one is not one.
      refute Enum.any?(Capability.live(), &(&1.component_sha256 == nil))

      assert %{name: ^live, component_sha256: @sha, id: id} = Capability.resolve(live)
      assert id == "wasm/" <> live
    end

    test "`resolve/1` answers nil for everything that is not one" do
      superseded = deploy("stale", @other_sha, :superseded)

      # A superseded rollout, a mesh agent that is not a capability, the lane prefix itself,
      # and rubbish. All the same answer, because this tool's refusal must not double as a
      # directory of what exists.
      for name <- [superseded, "agent-worker-7", "wasm/vet", "", "../etc", nil, 42] do
        assert Capability.resolve(name) == nil, "#{inspect(name)} resolved"
      end
    end

    test "a call to a name that is not live is refused, and no message is sent" do
      name = deploy_live("vet", @sha)
      _agent = worker("wasm/" <> name, %{"answered" => true})

      before = state("wasm/" <> name).last_message

      assert %{is_error: true, output: output} =
               call(%{"operation" => "call", "name" => "not-deployed", "message" => %{}})

      assert output =~ "no live capability"

      # The gate is before the mesh, not after it: the agent standing at the lane's own id
      # saw nothing.
      assert state("wasm/" <> name).last_message == before
    end
  end

  describe "list" do
    test "shows the register's identity, and labels the component's words as untrusted" do
      name = deploy_live("vet", @sha)
      _agent = worker("wasm/" <> name, %{"ok" => true})

      assert %{is_error: false, output: output} = call(%{"operation" => "list"})

      assert output =~ name
      assert output =~ @sha
      assert output =~ "running"

      # Nothing has described itself, and the listing says so rather than filling it in.
      assert output =~ "no description yet"
      assert output =~ "is this node's record"
    end

    test "an agent that is not running is said to be not running" do
      name = deploy_live("vet", @sha)

      assert %{output: output} = call(%{"operation" => "list"})
      assert output =~ name
      assert output =~ "not running"
    end

    test "a component's own describe is rendered under the untrusted label" do
      name = deploy_live("vet", @sha)

      _agent =
        worker("wasm/" <> name, %{"ok" => true}, %{
          describe:
            {:untrusted,
             {:ok,
              %{
                name: "vet",
                version: "1.2.3",
                world: Ouroboros.Wasm.world(),
                summary: "checks things",
                input_schema: nil,
                examples: [%{"message" => %{}, "reply" => %{}}]
              }}}
        })

      assert %{output: output} = call(%{"operation" => "list"})

      assert output =~ "[untrusted, authored by the component]"
      assert output =~ "checks things"
      assert output =~ "1 example(s)"

      # Every line carrying the component's words carries the label. A summary rendered on
      # its own line without one is the injection this lane exists to bound.
      for line <- String.split(output, "\n"), line =~ "checks things" do
        assert line =~ "[untrusted, authored by the component]"
      end
    end

    test "a malformed describe is said to be malformed, and never rendered" do
      name = deploy_live("vet", @sha)

      _agent =
        worker("wasm/" <> name, %{"ok" => true}, %{
          describe: {:untrusted, {:invalid, {:oversize_describe, 9_999, 4_096}}}
        })

      assert %{output: output} = call(%{"operation" => "list"})
      assert output =~ "malformed and was discarded"
      refute output =~ "9999"
    end
  end

  describe "call" do
    test "the reply comes back labelled, beside the identity of the bytes that produced it" do
      name = deploy_live("vet", @sha)
      id = worker("wasm/" <> name, %{"findings" => [], "checked" => 12})

      assert %{is_error: false, output: output} =
               call(%{"operation" => "call", "name" => name, "message" => %{"path" => "lib"}})

      assert output =~ @sha
      assert output =~ "[untrusted, authored by the component]"
      assert output =~ ~s("checked":12)

      # The message actually arrived, with the body the model wrote and nothing else.
      assert state(id).last_message.body == %{"path" => "lib"}
    end

    test "a body past the bound is refused before anything is sent" do
      name = deploy_live("vet", @sha)
      id = worker("wasm/" <> name, %{"ok" => true})

      before = state(id).last_message

      assert %{is_error: true, output: output} =
               call(%{
                 "operation" => "call",
                 "name" => name,
                 "message" => %{"blob" => String.duplicate("x", 65 * 1024)}
               })

      assert output =~ "the bound is 65536"
      assert state(id).last_message == before
    end

    test "a reply past the bound is cut on a whole character and marked" do
      name = deploy_live("vet", @sha)
      _id = worker("wasm/" <> name, String.duplicate("é", 60 * 1024))

      assert %{is_error: false, output: output} =
               call(%{"operation" => "call", "name" => name, "message" => %{}})

      assert output =~ "truncated at 65536 bytes"
      # Cut by bytes and walked back to a whole character, so what a renderer receives is
      # still text it can encode.
      assert String.valid?(output)
    end

    test "an unknown operation names the two that exist rather than guessing" do
      assert %{is_error: true, output: output} = call(%{"operation" => "invoke"})
      assert output =~ "list"
      assert output =~ "call"
    end

    test "an agent that is not running is a tool error, not a crash" do
      name = deploy_live("vet", @sha)

      assert %{is_error: true, output: output} =
               call(%{"operation" => "call", "name" => name, "message" => %{}})

      assert output =~ "no agent is running"
    end
  end

  describe "classification, and the permission request it produces" do
    test "list is a read and call is an execute" do
      assert Tools.classify("capability", %{"operation" => "list"}, scope()).mode == :read
      assert Tools.classify("capability", %{"operation" => "call"}, scope()).mode == :execute

      # An absent or unrecognised operation reads as the narrower of the two. The tool
      # refuses it a moment later; the engine must not have been told it was an execute it
      # could deny by mode alone, nor an execute it could allow.
      assert Tools.classify("capability", %{}, scope()).mode == :read
    end

    test "the context carries the name only when this node resolved it" do
      name = deploy_live("vet", @sha)

      resolved =
        Tools.classify("capability", %{"operation" => "call", "name" => name}, scope())

      assert resolved.context == %{capability: name, component_sha256: @sha}

      # The distinction that makes an allow on this honest: a name the register does not
      # call live contributes nothing, so `Capability(*)` cannot cover it either.
      unresolved =
        Tools.classify("capability", %{"operation" => "call", "name" => "invented"}, scope())

      assert unresolved.context == %{}
    end

    test "a rule keys on the capability, and the suggestion an operator is offered does too" do
      name = deploy_live("vet", @sha)
      classified = Tools.classify("capability", %{"operation" => "call", "name" => name}, scope())

      assert Permissions.suggest(request(classified)) == "Capability(#{name})"

      # Never the tool: `Tool(capability)` is "every component this node has deployed",
      # which is not what somebody answering one prompt about one capability meant.
      refute Permissions.suggest(request(classified)) == "Tool(capability)"
    end

    test "`Capability(<name>)` denies exactly that capability, and `Capability(*)` denies any" do
      name = deploy_live("vet", @sha)
      other = deploy_live("lint", @other_sha)

      classified = Tools.classify("capability", %{"operation" => "call", "name" => name}, scope())
      others = Tools.classify("capability", %{"operation" => "call", "name" => other}, scope())

      Application.put_env(:ouroboros, :permissions, [{"Capability(#{name})", :deny}])
      assert {:deny, _rule} = Permissions.evaluate(request(classified))
      assert {:ask, _reason} = Permissions.evaluate(request(others))

      Application.put_env(:ouroboros, :permissions, [{"Capability(*)", :deny}])
      assert {:deny, _rule} = Permissions.evaluate(request(classified))
      assert {:deny, _rule} = Permissions.evaluate(request(others))
    end

    test "an unresolved name is covered by no capability rule, not even the wildcard" do
      Application.put_env(:ouroboros, :permissions, [{"Capability(*)", :allow}])

      unresolved =
        Tools.classify("capability", %{"operation" => "call", "name" => "invented"}, scope())

      # An allow on `*` must not read as "we could not tell which capability this was".
      refute match?({:allow, _rule}, Permissions.evaluate(request(unresolved)))
    end

    test "with no rule at all the posture is ask" do
      name = deploy_live("vet", @sha)
      Application.delete_env(:ouroboros, :permissions)

      classified = Tools.classify("capability", %{"operation" => "call", "name" => name}, scope())
      assert {:ask, _reason} = Permissions.evaluate(request(classified))
    end
  end

  describe "the tool list" do
    test "the name is not taught on a node with nothing live" do
      for entry <- Registry.live(), do: retire(entry.artifact_id)

      refute "capability" in Enum.map(Tools.specs([], [], workspace: "/tmp"), & &1.name)
      assert Tools.lookup("capability", [], []) == {:error, :unknown_tool}
    end

    test "it appears, with its cost stated, once something is live" do
      _name = deploy_live("vet", @sha)

      spec = Enum.find(Tools.specs([], [], workspace: "/tmp"), &(&1.name == "capability"))

      assert spec
      # The helper is sequential, and a model choosing between this and a cheaper tool
      # should be able to read that off the tool list rather than discover it.
      assert spec.description =~ "single sandbox helper"
      assert spec.description =~ "untrusted"

      assert Tools.lookup("capability", [], []) == {:ok, Capability}
      assert Tools.lookup("capability", [], ["capability"]) == {:error, :unknown_tool}
    end
  end

  describe "through the loop" do
    setup do
      root = Path.join(System.tmp_dir!(), "capability-tool-#{System.unique_integer([:positive])}")
      File.mkdir_p!(Path.join(root, "workspace"))
      File.mkdir_p!(Path.join(root, "session"))
      on_exit(fn -> File.rm_rf(root) end)

      {:ok, scope} = Paths.scope(Path.join(root, "workspace"), [], :workspace_write)
      session_id = "capability-tool-#{System.unique_integer([:positive, :monotonic])}"

      %{
        scope: scope,
        session_dir: Path.join(root, "session"),
        session_id: session_id,
        principal: "session:" <> session_id
      }
    end

    test "a deny rule stops the call before the capability hears anything", context do
      name = deploy_live("vet", @sha)
      id = worker("wasm/" <> name, %{"ok" => true})
      before = state(id).last_message

      Application.put_env(:ouroboros, :permissions, [{"Capability(#{name})", :deny}])

      events =
        run_loop(context, [
          [
            {:tool_call,
             %{
               id: "c1",
               name: "capability",
               input: %{"operation" => "call", "name" => name, "message" => %{"go" => 1}}
             }}
          ],
          [{:text, "refused"}, {:finish, :stop}]
        ])

      result = find(events, :tool_result)
      assert result.payload["is_error"]

      # The whole point of a deny: the component was never asked. `:last_message` is the
      # agent's own record of what reached it, and it is unchanged.
      assert state(id).last_message == before
    end

    test "an allowed call is ledgered with the capability and the sha of its bytes", context do
      name = deploy_live("vet", @sha)
      _id = worker("wasm/" <> name, %{"ok" => true})

      Application.put_env(:ouroboros, :permissions, [{"Capability(#{name})", :allow}])

      events =
        run_loop(context, [
          [
            {:tool_call,
             %{
               id: "c1",
               name: "capability",
               input: %{"operation" => "call", "name" => name, "message" => %{"go" => 1}}
             }}
          ],
          [{:text, "done"}, {:finish, :stop}]
        ])

      refute find(events, :tool_result).payload["is_error"]

      assert {:ok, [entry]} =
               EffectLedger.list(principal: context.principal, effect: :tool_call)

      assert entry.attempt.tool == "capability"
      assert entry.attempt.subject.capability == name

      # D11 says a mesh message is not itself ledgered. This entry is therefore the only
      # written record that a model reached a component, and a name without the digest
      # would not say *which* component it was.
      assert entry.attempt.subject.component_sha256 == @sha

      # Never the body. The arguments are contents, and this ledger records identities.
      refute Map.has_key?(entry.attempt.subject, :message)
    end
  end

  ## Fixtures

  defp call(input), do: run_tool(input)

  defp run_tool(input) do
    {:ok, result} = Capability.run(input, %{})
    result
  end

  defp scope do
    %{root: System.tmp_dir!(), sandbox_mode: :workspace_write}
  end

  defp request(classified) do
    %{
      principal: %{session_id: "capability-tool", provider: :native, node: node()},
      tool: classified.tool,
      command: classified.command,
      paths: classified.paths,
      mode: classified.mode,
      domains: classified.domains,
      context: classified.context
    }
  end

  # One live lane-W rollout in this node's own register, under a name unique to this test,
  # retired at teardown so the next test's `live/0` does not inherit it.
  defp deploy_live(prefix, sha), do: deploy(prefix, sha, :live)

  defp deploy(prefix, sha, state) do
    name = "#{prefix}-#{System.unique_integer([:positive])}"
    artifact_id = "w13-#{System.unique_integer([:positive])}"

    {:ok, _entry} =
      Registry.deploying(
        artifact_id: artifact_id,
        module: "wasm/" <> name,
        epoch: System.unique_integer([:positive, :monotonic]),
        nodes: [node()],
        component_sha256: sha
      )

    # The register refuses transitions that would lose information, so a superseded entry is
    # reached the way a real one is: it was live first.
    {:ok, _entry} = Registry.mark(artifact_id, :live)
    if state != :live, do: {:ok, _entry} = Registry.mark(artifact_id, state)

    on_exit(fn -> retire(artifact_id) end)

    name
  end

  defp deploy_lane_b do
    artifact_id = "w13-lane-b-#{System.unique_integer([:positive])}"

    {:ok, _entry} =
      Registry.deploying(
        artifact_id: artifact_id,
        module: Ouroboros.Provider.Native.CapabilityToolTest,
        epoch: System.unique_integer([:positive, :monotonic]),
        nodes: [node()]
      )

    {:ok, _entry} = Registry.mark(artifact_id, :live)
    on_exit(fn -> retire(artifact_id) end)

    artifact_id
  end

  defp retire(artifact_id) do
    Registry.mark(artifact_id, :rolled_back)
  catch
    :exit, _reason -> :ok
  end

  # An agent standing at a lane id with a seeded answer. See the module doc for why this is
  # a `Worker` and not the wrapper.
  defp worker(id, answer, extra \\ %{}) do
    initial_state = Map.merge(%{last_answer: answer}, extra)

    {:ok, _pid} =
      Mesh.start_agent(id, agent: Ouroboros.Agent.Worker, initial_state: initial_state)

    on_exit(fn -> Mesh.stop_agent(id) end)

    id
  end

  defp state(id) do
    {:ok, %{agent: %{state: state}}} = Mesh.state(id)
    state
  end

  defp run_loop(context, script) do
    {model_spec, _agent} = NativeModelScript.start(script)
    test = self()

    loop = %Loop{
      emit: fn event -> send(test, {:event, event}) end,
      model_module: NativeModelScript,
      model_spec: model_spec,
      system: "system",
      scope: context.scope,
      session_dir: context.session_dir,
      session_id: context.session_id,
      provider_session_id: "capability-tool-test",
      turn_id: "turn-1",
      approval_mode: :auto_approve,
      approval_timeout_ms: 2_000
    }

    parent = self()
    spawn_link(fn -> send(parent, {:finished, Loop.run_turn(loop, "reach the capability")}) end)

    collect()
  end

  defp collect(acc \\ []) do
    receive do
      {:event, %{type: type} = event}
      when type in [:turn_completed, :turn_failed, :turn_interrupted] ->
        Enum.reverse([event | acc])

      {:event, event} ->
        collect([event | acc])
    after
      20_000 -> flunk("no terminal turn event within 20s")
    end
  end

  defp find(events, type), do: Enum.find(events, &(&1.type == type))
end
