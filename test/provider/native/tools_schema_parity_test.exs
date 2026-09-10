defmodule Ouroboros.Provider.Native.ToolsSchemaParityTest do
  use ExUnit.Case, async: false

  alias Ouroboros.NativeToolSchemaBaseline, as: Baseline
  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Provider.Native.Tools.Schema

  @fixture Path.expand("../../support/native_tool_schema_baseline/specs.json", __DIR__)
  @external_resource @fixture
  @baseline @fixture |> File.read!() |> JSON.decode!()

  test "every production and edge action retains its complete generated parameter schema" do
    actual =
      Map.new(Baseline.all_modules(), fn module ->
        {inspect(module), Schema.from_action(module)}
      end)

    assert Baseline.json(actual) === @baseline["generated"]
  end

  test "every final spec retains names, descriptions and model schema overrides" do
    Baseline.with_context(fn context ->
      actual =
        Map.new(Baseline.all_modules(), fn module ->
          {inspect(module), Tools.spec(module, context.options)}
        end)

      assert Baseline.json(actual) === @baseline["final"]

      for module <- [Tools.Plan, Tools.Agent, Tools.Capability, Tools.Forge] do
        expected = @baseline["final"][inspect(module)]["parameters"]
        assert actual[inspect(module)].parameters == expected

        if function_exported?(module, :model_schema, 0) do
          assert module.model_schema() == expected
          refute Schema.from_action(module) == expected
        else
          # Agent has no model_schema/0 in the pinned baseline; its generated
          # schema is the model contract and is equally covered by the oracle.
          assert Schema.from_action(module) == expected
        end
      end
    end)
  end

  test "description overrides and empty, nil and raised fallbacks remain exact" do
    assert Baseline.json(Baseline.description_specs()) === @baseline["descriptions"]
  end

  test "composed schemas preserve tool order, fleet/depth/filter/audit rules and skill budgets" do
    assert Baseline.json(Baseline.context_inputs()) === @baseline["context_inputs"]

    Baseline.with_context(fn context ->
      actual = Baseline.composed_specs(context)
      assert Baseline.json(actual) === @baseline["composed"]

      # Assert the fixture really exercises dynamic inclusion and exact MCP bypass,
      # rather than passing because the controlled fixtures were unavailable.
      names = Enum.map(actual["dynamic"], & &1.name)

      assert Enum.take(names, -4) ==
               ["capability", "forge", "mcp__fixture__open", "mcp__fixture__nested"]

      nested = Enum.find(actual["dynamic"], &(&1.name == "mcp__fixture__nested"))
      assert nested.parameters == Baseline.Nested.schema()
      assert nested.parameters["additionalProperties"] == true

      refute Map.has_key?(
               nested.parameters["properties"]["rows"]["items"],
               "additionalProperties"
             )

      for spec <- actual["mcp_deferred"] do
        assert spec.parameters == %{"type" => "object", "additionalProperties" => true}
      end
    end)
  end

  test "empty schemas normalize to the precise historical closed object" do
    assert Schema.from_action(Baseline.Empty) == %{
             "type" => "object",
             "properties" => %{},
             "required" => [],
             "additionalProperties" => false
           }
  end

  test "recursive defaults preserve explicit openness and schema-valued extra properties" do
    schema = Schema.from_action(Baseline.NonStrict)
    assert schema["additionalProperties"] == true
    assert schema["properties"]["open"]["additionalProperties"] == true

    assert schema["properties"]["dictionary"]["additionalProperties"] == %{
             "type" => "object",
             "properties" => %{},
             "additionalProperties" => false
           }

    assert schema["properties"]["rows"]["items"]["additionalProperties"] == false
    assert hd(schema["properties"]["choice"]["anyOf"])["additionalProperties"] == false
    assert hd(schema["allOf"])["additionalProperties"] == false

    strict = Schema.from_action(Baseline.Strict)
    assert strict["additionalProperties"] == false
    assert strict["properties"]["open"]["additionalProperties"] == false
    assert strict["properties"]["dictionary"]["additionalProperties"] == false
  end

  test "a cold action loads its strict callback before conversion" do
    cold = Baseline.Strict
    Code.ensure_loaded!(cold)
    :code.purge(cold)
    :code.delete(cold)
    refute function_exported?(cold, :strict?, 0)

    try do
      assert Schema.from_action(cold) === @baseline["generated"][inspect(cold)]
      assert function_exported?(cold, :strict?, 0)
    after
      Code.ensure_loaded!(cold)
    end
  end

  test "conversion loads the pinned action converter after it has been unloaded" do
    Code.ensure_loaded!(Jido.Action.Schema)
    :code.purge(Jido.Action.Schema)
    :code.delete(Jido.Action.Schema)
    refute function_exported?(Jido.Action.Schema, :to_json_schema, 2)

    try do
      assert Schema.from_action(Baseline.Defaults) ===
               @baseline["generated"][inspect(Baseline.Defaults)]
    after
      Code.ensure_loaded!(Jido.Action.Schema)
    end
  end
end
