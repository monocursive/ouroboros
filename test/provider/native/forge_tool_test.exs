defmodule Ouroboros.Provider.Native.ForgeToolTest.FakeForge do
  @moduledoc false

  # The module `Tools.Forge` reaches `Ouroboros.Wasm.Forge` through, named by
  # `config :ouroboros, :forge_module`. It records what it was asked and answers what the
  # test told it to — which is what makes "the forge was never called" a thing a test can
  # assert, rather than "the forge refused", which is a different claim entirely.
  #
  # Top level rather than nested inside the test module on purpose: a `defmodule` inside a
  # test module takes the outer module's prefix and shadows aliases.

  @name __MODULE__

  def start do
    case Agent.start(fn -> reset() end, name: @name) do
      {:ok, pid} -> pid
      {:error, {:already_started, pid}} -> Agent.update(pid, fn _state -> reset() end) && pid
    end
  end

  defp reset, do: %{calls: [], answers: %{}}

  @doc "What this fake answers one operation with: a term, or a zero-arity function."
  def answer(operation, answer),
    do: Agent.update(@name, fn state -> put_in(state.answers[operation], answer) end)

  @doc "Every call it received, oldest first, as `{operation, arguments}`."
  def calls, do: Agent.get(@name, &Enum.reverse(&1.calls))

  def called?(operation), do: Enum.any?(calls(), &(elem(&1, 0) == operation))

  @doc "The arguments of the one call to `operation`, or `nil`."
  def call(operation) do
    case Enum.filter(calls(), &(elem(&1, 0) == operation)) do
      [{^operation, arguments} | _rest] -> arguments
      [] -> nil
    end
  end

  def preview(input, opts), do: record(:preview, {input, opts})
  def forge(input, opts), do: record(:forge, {input, opts})
  def deploy(artifact, nodes, opts \\ []), do: record(:deploy, {artifact, nodes, opts})

  defp record(operation, arguments) do
    answer =
      Agent.get_and_update(@name, fn state ->
        {Map.get(state.answers, operation, {:error, {:no_answer_configured, operation}}),
         %{state | calls: [{operation, arguments} | state.calls]}}
      end)

    if is_function(answer, 0), do: answer.(), else: answer
  end
end

defmodule Ouroboros.Provider.Native.ForgeToolTest do
  @moduledoc """
  S1 — a session can change the runtime it runs in, and only through the fences.

  The claims here are the ones the tool is worth nothing without: it does not exist when
  the switch is off, `author` is the session and not a parameter, a path outside the
  workspace never reaches the forge, a bundle another principal signed is not deployable,
  and nothing is built that the effect ledger did not first record.

  Most of this runs against a fake forge named through `config :ouroboros, :forge_module`,
  because the assertions are about what reaches `Ouroboros.Wasm.Forge` and what does not —
  and "the forge was never called" is not a claim a real forge's refusal can support. The
  two places a real `Ouroboros.Wasm.Forge` is used are the ones where the *forge's own*
  judgement is the thing under test, and neither of them builds: a name that disagrees with
  the Cargo package is refused during validation, before cargo is spawned. The whole path
  with a real build is `test/wasm/forge_tool_acceptance_test.exs`.
  """

  # Not async: it moves `:native_forge_tool`, `:forge_module`, `:forge_tool_ledger`,
  # `:data_dir` and `:permissions`, all of which are global application environment.
  use ExUnit.Case, async: false

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Control.Permissions
  alias Ouroboros.Control.Permissions.Pattern
  alias Ouroboros.Control.Permissions.Rule
  alias Ouroboros.Provider.Native.ForgeToolTest.FakeForge
  alias Ouroboros.Provider.Native.Loop
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Permissions, as: NativePermissions
  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Provider.Native.Tools.Forge
  alias Ouroboros.Test.NativeModelScript
  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Wasm.Artifact
  alias Ouroboros.Wasm.Bundle
  alias Ouroboros.Wasm.ForgeFixture

  @moduletag :capture_log

  # A component preamble and nothing else: `Wasm.Artifact.build/2` reads the eight bytes and
  # the digest, and every test below that needs a bundle needs one it can decode rather than
  # one it can run.
  @component "\0asm" <> <<0x0D, 0x00, 0x01, 0x00>> <> "this is not a real component"

  setup do
    previous =
      Map.new(
        [:native_forge_tool, :forge_module, :forge_tool_ledger, :data_dir, :permissions],
        &{&1, Application.fetch_env(:ouroboros, &1)}
      )

    on_exit(fn ->
      Enum.each(previous, fn
        {key, {:ok, value}} -> Application.put_env(:ouroboros, key, value)
        {key, :error} -> Application.delete_env(:ouroboros, key)
      end)
    end)

    FakeForge.start()
    Application.put_env(:ouroboros, :native_forge_tool, true)
    Application.put_env(:ouroboros, :forge_module, FakeForge)

    root = Path.join(System.tmp_dir!(), "forge-tool-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    data_dir = Path.join(root, "data")
    File.mkdir_p!(workspace)
    File.mkdir_p!(Path.join(root, "session"))
    File.mkdir_p!(data_dir)
    on_exit(fn -> File.rm_rf(root) end)

    Application.put_env(:ouroboros, :data_dir, data_dir)

    {:ok, scope} = Paths.scope(workspace, [], :workspace_write)
    session_id = "forge-tool-#{System.unique_integer([:positive, :monotonic])}"

    %{
      root: root,
      workspace: scope.root,
      data_dir: data_dir,
      forged: Path.join([data_dir, "wasm", "forged"]),
      scope: scope,
      session_dir: Path.join(root, "session"),
      session_id: session_id,
      principal: "session:" <> session_id,
      context: %{scope: scope, principal: "session:" <> session_id}
    }
  end

  describe "the switch" do
    test "off, the name is neither taught nor resolvable", context do
      Application.put_env(:ouroboros, :native_forge_tool, false)

      refute Forge.enabled?()
      refute "forge" in Enum.map(Tools.specs([], [], workspace: context.workspace), & &1.name)
      assert Tools.lookup("forge", [], []) == {:error, :unknown_tool}
    end

    test "a switch that is not exactly `true` leaves it shut", context do
      for truthy <- ["true", 1, :yes, %{}] do
        Application.put_env(:ouroboros, :native_forge_tool, truthy)

        refute Forge.enabled?(), "#{inspect(truthy)} opened the tool"
        assert Tools.lookup("forge", [], []) == {:error, :unknown_tool}
        refute "forge" in Enum.map(Tools.specs([], [], workspace: context.workspace), & &1.name)
      end
    end

    test "on, it appears with its four operations and its cost stated", context do
      spec = Enum.find(Tools.specs([], [], workspace: context.workspace), &(&1.name == "forge"))

      assert spec
      assert spec.parameters["properties"]["operation"]["enum"] == ~w(preview forge deploy status)

      # A build is minutes of cargo and then the node's one helper. A model choosing between
      # this and anything else should read that off the tool list rather than discover it.
      assert spec.description =~ "minutes"
      assert spec.description =~ "preview"

      assert Tools.lookup("forge", [], []) == {:ok, Forge}
      assert Tools.lookup("forge", [], ["forge"]) == {:error, :unknown_tool}
      assert Tools.lookup("forge", ["read"], []) == {:error, :unknown_tool}
    end

    test "`author` is not a parameter of the schema at all", context do
      refute :author in Keyword.keys(Forge.schema())
      refute Map.has_key?(Forge.model_schema()["properties"], "author")

      # `additionalProperties: false` is the second half, and it is the *first* fence a
      # supplied one meets: the loop validates a call against the exact schema it advertised
      # this turn, so an argument the schema does not name never reaches the tool.
      assert Forge.model_schema()["additionalProperties"] == false

      specs = Tools.specs([], [], workspace: context.workspace)

      assert {:error, message} =
               Tools.validate_call(
                 "forge",
                 %{"operation" => "status", "author" => "session:somebody-else"},
                 specs
               )

      assert message =~ "Invalid arguments for `forge`"

      assert {:ok, _validated} = Tools.validate_call("forge", %{"operation" => "status"}, specs)
    end
  end

  describe "classification, and the permission request it produces" do
    test "every operation is an execute", context do
      for operation <- ~w(preview forge deploy status) do
        classified = classify(%{"operation" => operation, "name" => "vet"}, context)

        assert classified.mode == :execute, "#{operation} was not an execute"
      end

      # An absent or unrecognised operation is an execute too. This tool has no read half,
      # and a mode the engine could allow by being narrower than the tool would be a hole.
      assert classify(%{}, context).mode == :execute
    end

    test "the context carries the name only for the operations that pass it on", context do
      assert classify(%{"operation" => "forge", "name" => "vet"}, context).context ==
               %{forge: "vet"}

      assert classify(%{"operation" => "preview", "name" => "vet"}, context).context ==
               %{forge: "vet"}

      # A deploy names an artifact id. A `name` beside it is a string nothing will be held
      # to, so it is not put in front of the engine — a `Forge(vet)` allow must not become
      # permission to deploy whatever some id resolves to.
      assert classify(%{"operation" => "deploy", "name" => "vet", "artifact_id" => "a"}, context).context ==
               %{}

      assert classify(%{"operation" => "status", "name" => "vet"}, context).context == %{}
    end

    test "a name that is not a rollout name contributes nothing, exactly as written", context do
      for bad <- [
            "Vet",
            "vet/../etc",
            "wasm/vet",
            String.duplicate("a", 65),
            "",
            "-vet",
            nil,
            42
          ] do
        assert classify(%{"operation" => "forge", "name" => bad}, context).context == %{},
               "#{inspect(bad)} resolved for the engine"
      end
    end

    # F1. The finding this tool inherits: classification and execution must judge the same
    # bytes. A padded name is not a capability name for either of them.
    test "a padded name is refused by the engine and by the tool alike", context do
      padded = [
        <<0xA0::utf8>> <> "vet",
        "vet\n",
        " vet",
        "vet ",
        "\tvet",
        <<0x200B::utf8>> <> "vet"
      ]

      FakeForge.answer(:preview, {:ok, %{name: "vet"}})

      for evasive <- padded do
        assert classify(%{"operation" => "forge", "name" => evasive}, context).context == %{},
               "#{inspect(evasive)} resolved for the engine"

        assert %{is_error: true, output: output} =
                 run(%{"operation" => "preview", "name" => evasive, "path" => "."}, context)

        assert output =~ "is not a capability name", "#{inspect(evasive)} reached the tool"
      end

      refute FakeForge.called?(:preview)
    end

    test "the rule an operator is offered keys on what would be built", context do
      classified = classify(%{"operation" => "forge", "name" => "vet"}, context)

      assert Permissions.suggest(request(classified)) == "Forge(vet)"

      # Never the tool: an allow on `Tool(forge)` is an allow to add any capability to this
      # runtime, now and later.
      refute Permissions.suggest(request(classified)) == "Tool(forge)"

      # A deploy carries no name, so there is nothing honest to key a forge rule on and the
      # suggestion falls back to the narrowing form.
      deploy = classify(%{"operation" => "deploy", "artifact_id" => "a"}, context)
      assert Permissions.suggest(request(deploy)) == "Tool(forge)"
    end

    test "`Forge(<name>)` denies exactly that name and `Forge(*)` denies any", context do
      vet = classify(%{"operation" => "forge", "name" => "vet"}, context)
      lint = classify(%{"operation" => "forge", "name" => "lint"}, context)

      Application.put_env(:ouroboros, :permissions, [{"Forge(vet)", :deny}])
      assert {:deny, _rule} = Permissions.evaluate(request(vet))
      assert {:ask, _reason} = Permissions.evaluate(request(lint))

      Application.put_env(:ouroboros, :permissions, [{"Forge(*)", :deny}])
      assert {:deny, _rule} = Permissions.evaluate(request(vet))
      assert {:deny, _rule} = Permissions.evaluate(request(lint))
    end

    test "an unresolved name is covered by no forge rule, not even the wildcard", context do
      Application.put_env(:ouroboros, :permissions, [{"Forge(*)", :allow}])

      unresolved = classify(%{"operation" => "forge", "name" => "Vet"}, context)
      refute match?({:allow, _rule}, Permissions.evaluate(request(unresolved)))

      # And neither is a deploy, which is the operation that changes what runs.
      deploy = classify(%{"operation" => "deploy", "artifact_id" => "a"}, context)
      refute match?({:allow, _rule}, Permissions.evaluate(request(deploy)))
    end

    test "with no rule at all the posture is ask", context do
      Application.delete_env(:ouroboros, :permissions)

      classified = classify(%{"operation" => "forge", "name" => "vet"}, context)
      assert {:ask, _reason} = Permissions.evaluate(request(classified))
    end

    test "plan mode refuses every operation before the engine is asked", context do
      Application.put_env(:ouroboros, :permissions, [{"Forge(*)", :allow}])

      for operation <- ~w(preview forge deploy status) do
        classified = classify(%{"operation" => operation, "name" => "vet"}, context)

        planning =
          classified
          |> request()
          |> put_in([:context, :approval_mode], :plan)

        assert {:deny, {:plan_mode, :execute}} = NativePermissions.evaluate(planning),
               "plan mode allowed #{operation}"
      end
    end
  end

  describe "Tool(forge) cannot carry an allow" do
    test "the pattern says so, and every path that creates a rule honours it" do
      assert {:ok, pattern} = Pattern.parse("Tool(forge)")
      assert Pattern.decisions(pattern) == :deny_or_ask_only

      assert {:error, {:pattern_cannot_allow, "Tool(forge)"}} =
               Rule.new(%{scope: :node, decision: :allow, pattern: "Tool(forge)"})

      # Narrowing stays available, because narrowing is always honest.
      assert {:ok, _deny} = Rule.new(%{scope: :node, decision: :deny, pattern: "Tool(forge)"})
      assert {:ok, _ask} = Rule.new(%{scope: :node, decision: :ask, pattern: "Tool(forge)"})
    end

    test "a node config allow on the tool is dropped, so it covers nothing", context do
      Application.put_env(:ouroboros, :permissions, [{"Tool(forge)", :allow}])

      classified = classify(%{"operation" => "forge", "name" => "vet"}, context)

      refute match?({:allow, _rule}, Permissions.evaluate(request(classified))),
             "an any-capability-forever allow was honoured"
    end

    test "`Forge(*)` is how the broad thing is said out loud, and it does allow", context do
      Application.put_env(:ouroboros, :permissions, [{"Forge(*)", :allow}])

      classified = classify(%{"operation" => "forge", "name" => "vet"}, context)
      assert {:allow, _rule} = Permissions.evaluate(request(classified))
    end
  end

  describe "the author" do
    test "is the session's principal, and a parameter of that name never reaches the forge",
         context do
      project = project(context, "counter-a")
      FakeForge.answer(:forge, {:ok, receipt("counter-a")})

      # Through `Tools.execute/4` rather than `Forge.run/2`, because `Tools.atomize/2` is
      # where an undeclared argument is dropped and this is the assertion about it.
      result =
        Tools.execute(
          Forge,
          %{
            "operation" => "forge",
            "name" => "counter-a",
            "path" => project,
            "author" => "session:somebody-else"
          },
          context.context,
          10_000
        )

      refute result.is_error, result.output

      {_input, opts} = FakeForge.call(:forge)
      assert Keyword.fetch(opts, :author) == {:ok, context.principal}
      refute Keyword.get(opts, :author) == "session:somebody-else"
    end

    test "and not through the tool's own door either, under any spelling", context do
      project = project(context, "counter-a")
      FakeForge.answer(:forge, {:ok, receipt("counter-a")})

      # Straight at `run/2`, past the schema and past `Tools.atomize/2` — the two fences the
      # test above measures. What is left is the claim that matters on its own: nothing in
      # this module reads a parameter called `author`, however it is spelled.
      for spelling <- ["author", :author] do
        assert {:ok, %{is_error: false}} =
                 Forge.run(
                   %{
                     "operation" => "forge",
                     "name" => "counter-a",
                     "path" => project,
                     spelling => "session:somebody-else"
                   },
                   context.context
                 )

        {_input, opts} = FakeForge.call(:forge)

        assert Keyword.get(opts, :author) == context.principal,
               "an `#{spelling}` parameter reached the forge"
      end
    end

    test "a context with no principal refuses, and builds nothing", context do
      project = project(context, "counter-a")

      assert {:ok, %{is_error: true, output: output}} =
               Forge.run(
                 %{"operation" => "forge", "name" => "counter-a", "path" => project},
                 %{scope: context.scope}
               )

      assert output =~ "no session principal"
      refute FakeForge.called?(:forge)
    end

    test "the loop's anonymous principal is not an identity, and refuses", context do
      project = project(context, "counter-a")

      # `Ouroboros.Provider.Native.Loop.principal/1` answers `"native"` for a session with
      # no id of its own. Every such session is that one string, and `deploy` compares
      # authors — so signing under it would be one session able to deploy another's bytes.
      assert {:ok, %{is_error: true, output: output}} =
               Forge.run(
                 %{"operation" => "forge", "name" => "counter-a", "path" => project},
                 %{scope: context.scope, principal: "native"}
               )

      assert output =~ "no session principal"
      refute FakeForge.called?(:forge)
    end
  end

  describe "the path" do
    test "one outside the workspace is refused before the forge is called", context do
      outside = Path.join(context.root, "elsewhere")
      File.mkdir_p!(outside)

      for path <- [outside, "../elsewhere", "/etc", "/"] do
        assert %{is_error: true, output: output} =
                 run(%{"operation" => "forge", "name" => "counter-a", "path" => path}, context)

        assert output =~ "not usable", "#{path} was accepted"
      end

      refute FakeForge.called?(:forge)
    end

    test "one inside it reaches the forge canonicalised, as a directory", context do
      project = project(context, "counter-a")
      FakeForge.answer(:preview, {:ok, %{name: "counter-a", files: [], build: :skipped}})

      assert %{is_error: false} =
               run(
                 %{"operation" => "preview", "name" => "counter-a", "path" => "project"},
                 context
               )

      {input, opts} = FakeForge.call(:preview)
      assert input == %{dir: project}
      assert Keyword.get(opts, :name) == "counter-a"
      assert Keyword.get(opts, :build?) == true
    end

    test "a path that is a file, and a missing one, are refused", context do
      file = Path.join(context.workspace, "not-a-directory")
      File.write!(file, "")

      assert %{is_error: true, output: output} =
               run(%{"operation" => "forge", "name" => "counter-a", "path" => file}, context)

      assert output =~ "must name a directory"

      assert %{is_error: true} =
               run(%{"operation" => "forge", "name" => "counter-a", "path" => "nope"}, context)

      refute FakeForge.called?(:forge)
    end

    test "an absent path refuses rather than defaulting to the workspace", context do
      assert %{is_error: true, output: output} =
               run(%{"operation" => "forge", "name" => "counter-a"}, context)

      assert output =~ "`path` is required"
      refute FakeForge.called?(:forge)
    end
  end

  describe "the name, against the real forge" do
    setup do
      Application.put_env(:ouroboros, :forge_module, Ouroboros.Wasm.Forge)
      :ok
    end

    # `Wasm.Forge.preview/2` validates before it builds, and the package name is not a build
    # product — so this refuses without spawning cargo, which is why it can live here.
    test "a project whose Cargo package is called something else is refused", context do
      project = project(context, "counter-a")

      assert %{is_error: true, output: output} =
               run(%{"operation" => "preview", "name" => "counter-b", "path" => project}, context)

      assert output =~ "counter-a"
      assert output =~ "the capability's name"
    end

    test "the name the engine was shown is the name the forge is held to", context do
      project = project(context, "counter-a")

      # The whole of the honesty argument in one assertion: `context.forge` and the string
      # the forge refuses the project against are the same bytes.
      assert classify(%{"operation" => "forge", "name" => "counter-b"}, context).context ==
               %{forge: "counter-b"}

      assert %{is_error: true, output: output} =
               run(%{"operation" => "forge", "name" => "counter-b", "path" => project}, context)

      assert output =~ "counter-b"
      assert output =~ "counter-a"
    end
  end

  describe "the proposal manifest" do
    test "supplies the eval spec and the start config when the parameters are absent",
         context do
      project = project(context, "counter-a", manifest())
      FakeForge.answer(:forge, {:ok, receipt("counter-a")})

      assert %{is_error: false} =
               run(%{"operation" => "forge", "name" => "counter-a", "path" => project}, context)

      {_input, opts} = FakeForge.call(:forge)
      assert %{probes: [probe], budget_ms: 5_000, required: :all} = Keyword.get(opts, :eval)
      assert probe.input == %{"add" => 1}
      assert probe.expect == :any_reply
      assert Keyword.get(opts, :start_config) == "{\"step\": 2}"
    end

    test "a parameter wins over the file, through the same validator", context do
      project = project(context, "counter-a", manifest())
      FakeForge.answer(:forge, {:ok, receipt("counter-a")})

      assert %{is_error: false} =
               run(
                 %{
                   "operation" => "forge",
                   "name" => "counter-a",
                   "path" => project,
                   "eval" => %{
                     "probes" => [%{"input" => %{}, "expect" => ["contains", "ok"]}],
                     "budget_ms" => 1_234,
                     "required" => "all"
                   },
                   "start_config" => "{}"
                 },
                 context
               )

      {_input, opts} = FakeForge.call(:forge)
      assert %{budget_ms: 1_234, probes: [probe]} = Keyword.get(opts, :eval)
      assert probe.expect == {:contains, "ok"}
      assert Keyword.get(opts, :start_config) == "{}"
    end

    test "a manifest naming another capability is refused before the forge", context do
      project = project(context, "counter-a", manifest(name: "counter-z"))

      assert %{is_error: true, output: output} =
               run(%{"operation" => "forge", "name" => "counter-a", "path" => project}, context)

      assert output =~ "One capability, one name"
      refute FakeForge.called?(:forge)
    end

    test "a manifest this runtime cannot read is refused before the forge", context do
      for contents <- [
            "{",
            "[]",
            ~s({"name": "counter-a"}),
            ~s({"name": "Counter-A", "description": "d"})
          ] do
        project = project(context, "counter-a", contents)

        assert %{is_error: true, output: output} =
                 run(%{"operation" => "forge", "name" => "counter-a", "path" => project}, context)

        assert output =~ "manifest.json", "#{contents} was accepted"
      end

      refute FakeForge.called?(:forge)
    end

    test "an eval spec the evaluator refuses is refused before the forge", context do
      project = project(context, "counter-a")

      assert %{is_error: true, output: output} =
               run(
                 %{
                   "operation" => "forge",
                   "name" => "counter-a",
                   "path" => project,
                   "eval" => %{"probes" => "not a list"}
                 },
                 context
               )

      assert output =~ "`eval` was refused"
      refute FakeForge.called?(:forge)
    end

    # `Wasm.Forge.preview/2` answers `{:ok, report}` for a dry build that *failed*: the
    # preview succeeded in answering, and the build's own verdict is inside the report. A
    # renderer that read the shape rather than the verdict told a model its build had
    # succeeded and let it spend a forge finding out otherwise.
    test "a dry build that failed is never rendered as one that succeeded", context do
      project = project(context, "counter-a")

      FakeForge.answer(
        :preview,
        {:ok,
         %{
           name: "counter-a",
           files: [],
           build: %{
             outcome: :failed,
             ms: 42,
             reason: "{:build_failed, {:exit, 101, ...}}",
             output: "error[E0433]: failed to resolve: use of undeclared crate"
           }
         }}
      )

      assert %{is_error: false, output: output} =
               run(%{"operation" => "preview", "name" => "counter-a", "path" => project}, context)

      refute output =~ "dry build: succeeded"
      assert output =~ "dry build: FAILED after 42 ms"
      # The compiler's own words reach the model, because they are the answer.
      assert output =~ "undeclared crate"
    end

    test "a dry build that succeeded says what it produced", context do
      project = project(context, "counter-a")

      FakeForge.answer(
        :preview,
        {:ok,
         %{
           name: "counter-a",
           files: [],
           build: %{
             outcome: :ok,
             ms: 12,
             size: 4_096,
             component_sha256: String.duplicate("c", 64)
           }
         }}
      )

      assert %{is_error: false, output: output} =
               run(%{"operation" => "preview", "name" => "counter-a", "path" => project}, context)

      assert output =~ "dry build: succeeded in 12 ms; 4096 bytes"
      assert output =~ String.duplicate("c", 64)
    end

    test "a project with no manifest forges with neither, and the preview says so", context do
      project = project(context, "counter-a")
      FakeForge.answer(:preview, {:ok, %{name: "counter-a", files: [], build: :skipped}})
      FakeForge.answer(:forge, {:ok, receipt("counter-a")})

      assert %{is_error: false, output: output} =
               run(%{"operation" => "preview", "name" => "counter-a", "path" => project}, context)

      # The signer requires an evaluation by default, so a preview that did not say this
      # would be a preview whose "would be accepted" was not true of the next call.
      assert output =~ "no evaluation spec"

      assert %{is_error: false} =
               run(%{"operation" => "forge", "name" => "counter-a", "path" => project}, context)

      {_input, opts} = FakeForge.call(:forge)
      refute Keyword.has_key?(opts, :eval)
      refute Keyword.has_key?(opts, :start_config)
    end
  end

  describe "the ledger" do
    test "the entry exists and is started before the forge runs, and is settled after",
         context do
      project = project(context, "counter-a")
      test_process = self()

      FakeForge.answer(:forge, fn ->
        send(test_process, {:ledger_during, entries(context.principal, :forge)})
        {:ok, receipt("counter-a")}
      end)

      assert %{is_error: false, output: output} =
               run(%{"operation" => "forge", "name" => "counter-a", "path" => project}, context)

      assert output =~ "Forged and signed counter-a"

      assert_received {:ledger_during, [during]}
      assert during.status == :started
      assert during.effect == :forge
      assert during.principal == context.principal
      assert during.attempt == %{module: "wasm/counter-a"}

      # Bytes never enter the ledger: the attempt names the module and nothing else.
      refute Map.has_key?(during.attempt, :source)

      [settled] = entries(context.principal, :forge)
      assert settled.id == during.id
      assert settled.status == :ok
      assert settled.result.artifact_id == "artifact-counter-a"
      assert settled.result.source_sha256 == String.duplicate("a", 64)
      assert settled.result.nodes == [node()]
      assert settled.authority.decision == :granted
    end

    test "the cause names the tool call this ran inside", context do
      project = project(context, "counter-a")
      FakeForge.answer(:forge, {:ok, receipt("counter-a")})

      audit = %{stream: "s", fields: %{"ledger_effect_id" => "tool-abc", "call_id" => "c1"}}

      assert {:ok, %{is_error: false}} =
               Forge.run(
                 %{"operation" => "forge", "name" => "counter-a", "path" => project},
                 Map.put(context.context, :audit, audit)
               )

      [entry] = entries(context.principal, :forge)

      # The chain to the permission decision: this entry's cause names the `:tool_call`
      # entry, whose own attempt names the `:permission` entry. Two hops, each written by
      # whichever thing knew the fact.
      assert entry.cause.signal_id == "tool-abc"
      assert entry.cause.signal_type == "native.tool.forge.forge"
    end

    test "a refusal is settled as failed, with the class and not the text", context do
      project = project(context, "counter-a")
      FakeForge.answer(:forge, {:error, {:build_failed, "a secret path /home/somebody/x"}})

      assert %{is_error: true, output: output} =
               run(%{"operation" => "forge", "name" => "counter-a", "path" => project}, context)

      assert output =~ "forge refused"

      [entry] = entries(context.principal, :forge)
      assert entry.status == :failed
      assert entry.error.classification == {:forge_refused, :build_failed}
    end

    test "a ledger that cannot record stops the forge", context do
      project = project(context, "counter-a")
      FakeForge.answer(:forge, {:ok, receipt("counter-a")})

      Application.put_env(:ouroboros, :forge_tool_ledger, :a_ledger_that_is_not_running)

      assert %{is_error: true, output: output} =
               run(%{"operation" => "forge", "name" => "counter-a", "path" => project}, context)

      assert output =~ "could not record this forge before it ran, so it did not run"

      # The whole claim: not "it ran and was not recorded".
      refute FakeForge.called?(:forge)
    end

    test "a ledger that cannot record stops a deploy too", context do
      artifact = bundle!(context, "counter-a", context.principal)
      FakeForge.answer(:deploy, {:ok, %{state: :live}})

      Application.put_env(:ouroboros, :forge_tool_ledger, :a_ledger_that_is_not_running)

      assert %{is_error: true, output: output} =
               run(%{"operation" => "deploy", "artifact_id" => artifact.id}, context)

      assert output =~ "could not record this deploy"
      refute FakeForge.called?(:deploy)
    end
  end

  describe "deploy" do
    test "ships a bundle this session forged, and settles the entry with it", context do
      artifact = bundle!(context, "counter-a", context.principal)
      FakeForge.answer(:deploy, {:ok, %{state: :live}})

      assert %{is_error: false, output: output} =
               run(%{"operation" => "deploy", "artifact_id" => artifact.id}, context)

      assert output =~ "counter-a is :live"
      assert output =~ artifact.component_sha256

      {deployed, nodes, _opts} = FakeForge.call(:deploy)
      assert deployed.id == artifact.id
      assert nodes == [node()]

      [entry] = entries(context.principal, :deploy)
      assert entry.status == :ok
      assert entry.attempt == %{nodes: [node()]}
      assert entry.result.artifact_id == artifact.id
      assert entry.result.module == "wasm/counter-a"
      assert entry.result.state == :live
    end

    test "refuses a bundle another principal forged, and does not deploy it", context do
      artifact = bundle!(context, "counter-a", "session:somebody-else")
      FakeForge.answer(:deploy, {:ok, %{state: :live}})

      assert %{is_error: true, output: output} =
               run(%{"operation" => "deploy", "artifact_id" => artifact.id}, context)

      assert output =~ "forged by another principal"
      refute FakeForge.called?(:deploy)

      # And nothing was recorded as started either: the refusal is before the ledger entry,
      # because a deploy that was never admitted has no attempt to account for.
      assert entries(context.principal, :deploy) == []
    end

    test "an artifact id that is not one never becomes a path", context do
      # A perfectly good bundle, signed by this very principal, one directory above the
      # ring. It is exactly what a `..` in an id reaches if the id is not held to a charset
      # *before* a filename is built from it — so this is the difference between "the read
      # missed" and "the read never left the ring".
      escape =
        bundle!(context, "counter-a", context.principal, Path.join(context.data_dir, "wasm"))

      FakeForge.answer(:deploy, {:ok, %{state: :live}})

      assert %{is_error: true, output: output} =
               run(%{"operation" => "deploy", "artifact_id" => "../" <> escape.id}, context)

      assert output =~ "not an artifact id"

      for id <- ["../../etc/passwd", "a/b", ".", "", String.duplicate("a", 65), "a b", "x.y"] do
        assert %{is_error: true, output: refusal} =
                 run(%{"operation" => "deploy", "artifact_id" => id}, context)

        assert refusal =~ "not an artifact id", "#{inspect(id)} was read as an id"
      end

      refute FakeForge.called?(:deploy)
    end

    test "an id nothing is filed under is a refusal that is not a directory listing",
         context do
      assert %{is_error: true, output: output} =
               run(%{"operation" => "deploy", "artifact_id" => "artifact-nothing"}, context)

      assert output =~ "no bundle this node forged"
      refute FakeForge.called?(:deploy)
    end

    test "a rollout that did not go live is reported as what it is", context do
      artifact = bundle!(context, "counter-a", context.principal)
      FakeForge.answer(:deploy, {:ok, %{state: :quarantined}})

      assert %{is_error: false, output: output} =
               run(%{"operation" => "deploy", "artifact_id" => artifact.id}, context)

      assert output =~ ":quarantined"

      [entry] = entries(context.principal, :deploy)
      assert entry.result.state == :quarantined
    end
  end

  describe "status" do
    test "lists this session's bundles and the register's answer about each", context do
      mine = bundle!(context, "counter-a", context.principal)
      theirs = bundle!(context, "counter-b", "session:somebody-else")

      assert %{is_error: false, output: output} =
               run(%{"operation" => "status"}, context)

      assert output =~ mine.id
      assert output =~ "counter-a"
      assert output =~ "not deployed"

      # Another principal's bundle is in the same ring and is not this session's business.
      refute output =~ theirs.id
      refute output =~ "counter-b"
    end

    test "says so when there is nothing", context do
      assert %{is_error: false, output: output} = run(%{"operation" => "status"}, context)
      assert output =~ "forged nothing"
    end

    test "reports the register state of one that was deployed", context do
      artifact = bundle!(context, "counter-a", context.principal)

      {:ok, _entry} =
        Registry.deploying(
          artifact_id: artifact.id,
          module: "wasm/counter-a",
          epoch: System.unique_integer([:positive, :monotonic]),
          nodes: [node()],
          component_sha256: artifact.component_sha256
        )

      {:ok, _entry} = Registry.mark(artifact.id, :live)
      on_exit(fn -> retire(artifact.id) end)

      assert %{is_error: false, output: output} = run(%{"operation" => "status"}, context)
      assert output =~ ":live"
    end
  end

  describe "the operation itself" do
    test "an unknown one names the four that exist rather than guessing", context do
      assert %{is_error: true, output: output} = run(%{"operation" => "build"}, context)

      for operation <- ~w(preview forge deploy status), do: assert(output =~ operation)
      refute FakeForge.called?(:forge)
    end

    test "an operation is not trimmed into a different one", context do
      assert %{is_error: true, output: output} = run(%{"operation" => " forge "}, context)
      assert output =~ "must be"
      refute FakeForge.called?(:forge)
    end
  end

  describe "through the loop" do
    test "a deny stops the call before anything is built", context do
      _project = project(context, "counter-a")
      Application.put_env(:ouroboros, :permissions, [{"Forge(counter-a)", :deny}])

      events =
        run_loop(context, [
          [
            {:tool_call,
             %{
               id: "c1",
               name: "forge",
               input: %{
                 "operation" => "forge",
                 "name" => "counter-a",
                 "path" => "project"
               }
             }}
          ],
          [{:text, "refused"}, {:finish, :stop}]
        ])

      assert find(events, :tool_result).payload["is_error"]
      refute FakeForge.called?(:forge)
    end

    test "an allowed call carries the loop's own principal into the signed manifest",
         context do
      _project = project(context, "counter-a")
      FakeForge.answer(:forge, {:ok, receipt("counter-a")})
      Application.put_env(:ouroboros, :permissions, [{"Forge(counter-a)", :allow}])

      events =
        run_loop(context, [
          [
            {:tool_call,
             %{
               id: "c1",
               name: "forge",
               input: %{
                 "operation" => "forge",
                 "name" => "counter-a",
                 "path" => "project"
               }
             }}
          ],
          [{:text, "done"}, {:finish, :stop}]
        ])

      refute find(events, :tool_result).payload["is_error"]

      {_input, opts} = FakeForge.call(:forge)
      assert Keyword.get(opts, :author) == context.principal

      # The tool call is ledgered like every other one, and the forge has its own entry
      # beside it under the same principal.
      assert {:ok, [tool_call]} =
               EffectLedger.list(principal: context.principal, effect: :tool_call)

      assert tool_call.attempt.tool == "forge"
      assert [%{effect: :forge, status: :ok}] = entries(context.principal, :forge)
    end
  end

  ## Fixtures

  defp run(input, context), do: elem(Forge.run(input, context.context), 1)

  defp classify(input, context), do: Tools.classify("forge", input, context.scope)

  defp request(classified) do
    %{
      principal: %{session_id: "forge-tool", provider: :native, node: node()},
      tool: classified.tool,
      command: classified.command,
      paths: classified.paths,
      mode: classified.mode,
      domains: classified.domains,
      context: classified.context
    }
  end

  # The counter example, renamed, in a directory inside this session's workspace. A real
  # C9-shaped project, so the tests that use the real forge are refused for the reason under
  # test rather than for a missing file.
  defp project(context, name, manifest \\ nil) do
    dir = Path.join(context.workspace, "project")
    File.rm_rf(dir)
    File.mkdir_p!(Path.join(dir, "src"))

    Enum.each(ForgeFixture.counter(name), fn {path, contents} ->
      File.write!(Path.join(dir, path), contents)
    end)

    if manifest, do: File.write!(Path.join(dir, "manifest.json"), manifest)

    dir
  end

  defp manifest(opts \\ []) do
    JSON.encode!(%{
      "name" => Keyword.get(opts, :name, "counter-a"),
      "description" => "a counter that counts",
      "eval" => %{
        "probes" => [%{"input" => %{"add" => 1}, "expect" => "any_reply"}],
        "budget_ms" => 5_000,
        "required" => "all"
      },
      "start" => %{"config" => "{\"step\": 2}"}
    })
  end

  # What `Ouroboros.Wasm.Forge.forge/2` answers with, reduced to the fields this tool reads.
  defp receipt(name) do
    %{
      artifact_id: "artifact-" <> name,
      name: name,
      module: "wasm/" <> name,
      epoch: 7,
      component_sha256: String.duplicate("c", 64),
      size: 1_024,
      imports: ["log"],
      world: Ouroboros.Wasm.world(),
      signer: "s1-test",
      source_sha256: String.duplicate("a", 64)
    }
  end

  # One decodable bundle in this node's forged ring, authored by `author`. Not runnable and
  # not meant to be: what the ring is read for is a manifest, and a manifest is what this
  # writes.
  defp bundle!(context, name, author, directory \\ nil) do
    {:ok, artifact} =
      Artifact.build(@component,
        name: name,
        epoch: System.unique_integer([:positive, :monotonic]),
        author: author,
        imports: ["log"]
      )

    {:ok, signed} =
      Artifact.with_signature(artifact, %{
        signer: "s1-test",
        value: :crypto.strong_rand_bytes(64)
      })

    {:ok, bundle} = Bundle.encode(signed, @component)
    directory = directory || context.forged
    File.mkdir_p!(directory)
    File.write!(Path.join(directory, signed.id <> Bundle.extension()), bundle)

    signed
  end

  defp entries(principal, effect) do
    {:ok, entries} = EffectLedger.list(principal: principal, effect: effect)
    entries
  end

  defp retire(artifact_id) do
    Registry.mark(artifact_id, :rolled_back)
  catch
    :exit, _reason -> :ok
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
      provider_session_id: "forge-tool-test",
      turn_id: "turn-1",
      approval_mode: :auto_approve,
      approval_timeout_ms: 2_000
    }

    parent = self()
    spawn_link(fn -> send(parent, {:finished, Loop.run_turn(loop, "forge a capability")}) end)

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
      30_000 -> flunk("no terminal turn event within 30s")
    end
  end

  defp find(events, type), do: Enum.find(events, &(&1.type == type))
end
