defmodule Ouroboros.Provider.Native.ToolsBehaviorParityTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Provider.Native.Model.ToolSchema
  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Test.NativeToolBehaviorBaseline, as: Baseline

  @fixture_path Path.expand("../../support/fixtures/native_tool_behavior_baseline.exs", __DIR__)
  @external_resource @fixture_path
  {fixture, []} = Code.eval_file(@fixture_path)
  @baseline fixture.captured

  test "preserves every baseline JSON validation result and complete diagnostic" do
    Baseline.with_context(fn ->
      specs = Baseline.specs()

      for entry <- @baseline.validation do
        assert Tools.validate_call(entry.name, entry.input, specs) === entry.result,
               "local JSON validation changed for #{entry.id}"
      end
    end)
  end

  test "preserves effective action arguments, defaults, key conversion and visible errors" do
    Baseline.with_context(fn ->
      for entry <- @baseline.action do
        assert Baseline.observe_action(entry.input) === entry.observation,
               "action validation or execution changed for #{entry.id}"
      end
    end)
  end

  test "preserves complete transport schemas, strictness and description hints" do
    Baseline.with_context(fn ->
      specs = Baseline.specs()

      for transport <- @baseline.transport do
        actual =
          specs
          |> ToolSchema.prepare(transport.model)
          |> Enum.map(&Map.take(&1, [:name, :description, :parameter_schema, :strict]))

        assert actual === transport.tools, "prepared tools changed for #{transport.id}"
      end
    end)
  end

  test "preserves synthetic optional null restoration through nested objects and arrays" do
    Baseline.with_context(fn ->
      specs = Baseline.specs()

      for entry <- @baseline.restoration do
        assert ToolSchema.restore_input(specs, entry.name, entry.input) === entry.restored,
               "input restoration changed for #{entry.id}"
      end
    end)
  end

  test "a valid model call passes unchanged through local validation into baseline effective inputs" do
    Baseline.with_context(fn ->
      specs = Baseline.specs()

      for id <- ["defaults", "explicit_values"] do
        entry = Enum.find(@baseline.action, &(&1.id == id))

        assert {:ok, validated} =
                 Tools.validate_call("native_contract_probe", entry.input, specs)

        assert Baseline.observe_action(validated) === entry.observation
      end
    end)
  end
end

defmodule Ouroboros.Provider.Native.ToolsBehaviorParityLoopTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Provider.Native.Loop
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Test.NativeModelScript

  defmodule PermissionProbe do
    def evaluate(request) do
      send(Application.fetch_env!(:ouroboros, :native_behavior_observer), {:permission, request})
      {:deny, :baseline_probe}
    end
  end

  setup do
    root =
      Path.join(System.tmp_dir!(), "native-parity-loop-#{System.unique_integer([:positive])}")

    File.mkdir_p!(root)
    session_dir = Path.join(root, "session")
    File.mkdir_p!(session_dir)
    {:ok, scope} = Paths.scope(root, [], :workspace_write)
    keys = [:audit, :permissions_engine, :native_behavior_observer]
    previous = Map.new(keys, &{&1, Application.fetch_env(:ouroboros, &1)})
    Application.put_env(:ouroboros, :audit, mode: :standard)
    Application.put_env(:ouroboros, :permissions_engine, PermissionProbe)
    Application.put_env(:ouroboros, :native_behavior_observer, self())

    on_exit(fn ->
      Enum.each(previous, fn
        {key, {:ok, value}} -> Application.put_env(:ouroboros, key, value)
        {key, :error} -> Application.delete_env(:ouroboros, key)
      end)

      File.rm_rf!(root)
    end)

    %{root: root, scope: scope, session_dir: session_dir}
  end

  test "invalid calls reach neither permission dispatch nor a write effect", context do
    inputs = [
      %{"path" => "must-not-exist"},
      %{"path" => "must-not-exist", "content" => 1},
      %{"path" => "must-not-exist", "content" => nil},
      %{"path" => "must-not-exist", "content" => "blocked", "unknown" => true}
    ]

    spec = Tools.spec(Tools.Write)
    calls = Enum.with_index(inputs, &%{id: "invalid-#{&2}", name: "write", input: &1})
    events = run_calls(context, calls, spec)
    results = Enum.filter(events, &(&1.type == :tool_result))

    assert length(results) == length(calls)

    for {call, result} <- Enum.zip(calls, results) do
      assert {:error, expected} = Tools.validate_call(call.name, call.input, [spec])
      assert result.payload["is_error"]
      assert result.payload["output"] == expected
    end

    for event <- Enum.filter(events, &(&1.type == :tool_call)) do
      refute Map.has_key?(event.payload, "ledger_ref")
    end

    refute_receive {:permission, _request}
    refute Enum.any?(events, &(&1.type in [:approval_requested, :file_change]))
    refute File.exists?(Path.join(context.root, "must-not-exist"))
    assert List.last(events).type == :turn_completed
  end

  test "the permission probe observes a valid loop call as a positive control", context do
    input = %{"path" => "must-not-exist", "content" => "valid, then denied"}
    spec = Tools.spec(Tools.Write)
    assert {:ok, ^input} = Tools.validate_call("write", input, [spec])
    call = %{id: "valid-control", name: "write", input: input}
    events = run_calls(context, [call], spec)

    assert_receive {:permission, %{tool: "write", mode: :write, paths: [path]}}
    assert path == Path.join(context.scope.root, "must-not-exist")
    refute_receive {:permission, _second_request}
    result = Enum.find(events, &(&1.type == :tool_result))
    assert result.payload["is_error"]
    assert result.payload["output"] =~ "baseline_probe"
    refute File.exists?(path)
    assert List.last(events).type == :turn_completed
  end

  defp run_calls(context, calls, spec) do
    script = Enum.map(calls, &[{:tool_call, &1}]) ++ [[{:text, "recovered"}, {:finish, :stop}]]
    {model_spec, _agent} = NativeModelScript.start(script)
    observer = self()

    loop = %Loop{
      emit: fn event -> send(observer, {:event, event}) end,
      model_module: NativeModelScript,
      model_spec: model_spec,
      system: "Synthetic argument-validation parity check.",
      scope: context.scope,
      session_dir: context.session_dir,
      session_id: "native-parity",
      provider_session_id: "native-parity-provider",
      turn_id: "native-parity-turn",
      approval_mode: :auto_approve,
      tool_specs: [spec],
      allowed_tools: ["write"]
    }

    spawn_link(fn ->
      send(observer, {:finished, Loop.run_turn(loop, "Validate synthetic calls")})
    end)

    events = collect([])
    assert_receive {:finished, _loop}, 5_000
    events
  end

  defp collect(events) do
    receive do
      {:event, %{type: type} = event}
      when type in [:turn_completed, :turn_failed, :turn_interrupted] ->
        Enum.reverse([event | events])

      {:event, event} ->
        collect([event | events])
    after
      30_000 -> flunk("the scripted native loop did not complete")
    end
  end
end
