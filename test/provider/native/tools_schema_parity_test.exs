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

    actual = strip_authorized_additions(actual)
    assert Baseline.json(actual) === @baseline["generated"]
  end

  test "every final spec retains names, descriptions and model schema overrides" do
    Baseline.with_context(fn context ->
      actual =
        Map.new(Baseline.all_modules(), fn module ->
          {inspect(module), Tools.spec(module, context.options)}
        end)

      frozen_actual = strip_authorized_additions(Baseline.json(actual))
      assert frozen_actual === @baseline["final"]

      for module <- [Tools.Plan, Tools.Agent, Tools.Capability, Tools.Forge] do
        expected = @baseline["final"][inspect(module)]["parameters"]

        compared =
          cond do
            module == Tools.Plan ->
              legacy_plan_schema(actual[inspect(module)].parameters)

            module == Tools.Agent ->
              update_in(
                actual[inspect(module)].parameters,
                ["properties"],
                &Map.delete(&1, "work_item_ids")
              )

            true ->
              actual[inspect(module)].parameters
          end

        assert compared == expected

        if function_exported?(module, :model_schema, 0) do
          model_schema = module.model_schema()

          compared_model =
            cond do
              module == Tools.Plan ->
                legacy_plan_schema(model_schema)

              module == Tools.Agent ->
                update_in(model_schema, ["properties"], &Map.delete(&1, "work_item_ids"))

              true ->
                model_schema
            end

          assert compared_model == expected
          refute Schema.from_action(module) == expected
        else
          # Agent has no model_schema/0 in the pinned baseline; its generated
          # schema is the model contract after removing the authorized work-item binding.
          generated = Schema.from_action(module)

          compared_generated =
            if module == Tools.Agent,
              do: update_in(generated, ["properties"], &Map.delete(&1, "work_item_ids")),
              else: generated

          assert compared_generated == expected
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
      frozen_actual = strip_authorized_additions(Baseline.json(actual))
      assert frozen_actual === @baseline["composed"]

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

  test "conversion loads the owned action converter after it has been unloaded" do
    Code.ensure_loaded!(Ouroboros.Action.Schema)
    :code.purge(Ouroboros.Action.Schema)
    :code.delete(Ouroboros.Action.Schema)
    refute function_exported?(Ouroboros.Action.Schema, :to_json_schema, 2)

    try do
      assert Schema.from_action(Baseline.Defaults) ===
               @baseline["generated"][inspect(Baseline.Defaults)]
    after
      Code.ensure_loaded!(Ouroboros.Action.Schema)
    end
  end

  test "authorized tool additions are present with their exact independent contracts" do
    bash = Tools.spec(Tools.Bash)
    bash_frozen = @baseline["final"][inspect(Tools.Bash)]

    assert MapSet.difference(
             MapSet.new(Map.keys(bash.parameters["properties"])),
             MapSet.new(Map.keys(bash_frozen["parameters"]["properties"]))
           ) == MapSet.new(["retry_attempt_id"])

    assert bash.parameters["required"] == bash_frozen["parameters"]["required"]

    assert bash.parameters["properties"]["retry_attempt_id"] == %{
             "type" => "string",
             "description" =>
               "Only use the exact runtime-issued id from the immediately retained failed attempt. " <>
                 "Omit this field on every new command; never guess or reuse an id. A retry must " <>
                 "keep the command, cwd, sandbox mode, and paths identical."
           }

    result = Tools.spec(Tools.AgentResult)
    result_frozen = @baseline["final"][inspect(Tools.AgentResult)]
    properties = result.parameters["properties"]

    assert MapSet.difference(
             MapSet.new(Map.keys(properties)),
             MapSet.new(Map.keys(result_frozen["parameters"]["properties"]))
           ) == MapSet.new(["cursor", "max_bytes", "release"])

    assert result.parameters["required"] == result_frozen["parameters"]["required"]

    assert properties["cursor"] == %{
             "type" => "integer",
             "minimum" => 0,
             "description" =>
               "Byte cursor returned by a prior page. Omit for the concise summary."
           }

    assert properties["max_bytes"] == %{
             "type" => "integer",
             "minimum" => 1,
             "description" => "Maximum UTF-8 report bytes to return for a page. Maximum 12288."
           }

    assert properties["release"] == %{
             "type" => "boolean",
             "description" =>
               "Explicitly release a terminal child after this successful summary or page read."
           }

    plan = Tools.spec(Tools.Plan)
    generated_plan = Schema.from_action(Tools.Plan)
    legacy_generated = @baseline["generated"][inspect(Tools.Plan)]

    assert MapSet.difference(
             MapSet.new(Map.keys(generated_plan["properties"])),
             MapSet.new(Map.keys(legacy_generated["properties"]))
           ) == MapSet.new(["accept"])

    assert generated_plan["properties"]["accept"]["type"] == "array"

    legacy_plan = @baseline["final"][inspect(Tools.Plan)]["parameters"]

    assert MapSet.difference(
             MapSet.new(Map.keys(plan.parameters["properties"])),
             MapSet.new(Map.keys(legacy_plan["properties"]))
           ) == MapSet.new(["accept"])

    assert plan.parameters["properties"]["accept"] == %{
             "type" => "array",
             "description" =>
               "Work-item IDs this owning parent accepts; acceptance requires criteria and evidence.",
             "items" => %{"type" => "string"},
             "maxItems" => 40
           }

    item = plan.parameters["properties"]["steps"]["items"]

    assert MapSet.difference(
             MapSet.new(Map.keys(item["properties"])),
             MapSet.new(Map.keys(legacy_plan["properties"]["steps"]["items"]["properties"]))
           ) ==
             MapSet.new(
               ~w(id deliverable work_state owner_task_id criteria evidence child_settlement blocker acceptance)
             )

    agent = Tools.spec(Tools.Agent)
    baseline_agent = @baseline["final"][inspect(Tools.Agent)]

    assert MapSet.difference(
             MapSet.new(Map.keys(agent.parameters["properties"])),
             MapSet.new(Map.keys(baseline_agent["parameters"]["properties"]))
           ) == MapSet.new(["work_item_ids"])

    assert agent.parameters["properties"]["work_item_ids"] == %{
             "type" => "array",
             "items" => %{"type" => "string"},
             "description" =>
               "Existing parent work-item IDs delegated to this child. Their criteria and deliverable are bound before execution."
           }

    safe_status = Tools.spec(Tools.SafeStatus)
    assert safe_status.name == "safe_status"

    assert safe_status.parameters == %{
             "type" => "object",
             "properties" => %{},
             "required" => [],
             "additionalProperties" => false
           }
  end

  defp strip_authorized_additions(value) when is_map(value) do
    value = Map.new(value, fn {key, nested} -> {key, strip_authorized_additions(nested)} end)

    value
    |> Map.delete("Ouroboros.Provider.Native.Tools.SafeStatus")
    |> strip_module_schema("Ouroboros.Provider.Native.Tools.Bash", ["retry_attempt_id"])
    |> strip_module_schema("Ouroboros.Provider.Native.Tools.Agent", ["work_item_ids"])
    |> strip_module_schema(
      "Ouroboros.Provider.Native.Tools.AgentResult",
      ["cursor", "max_bytes", "release"]
    )
    |> strip_plan_schema()
    |> strip_named_spec()
  end

  defp strip_authorized_additions(value) when is_list(value),
    do: value |> Enum.map(&strip_authorized_additions/1) |> Enum.reject(&is_nil/1)

  defp strip_authorized_additions(value), do: value

  defp strip_module_schema(value, module, fields) do
    case value do
      %{^module => %{"properties" => properties}} ->
        put_in(value, [module, "properties"], Map.drop(properties, fields))

      %{^module => %{"parameters" => %{"properties" => properties}}} ->
        put_in(value, [module, "parameters", "properties"], Map.drop(properties, fields))

      _ ->
        value
    end
  end

  defp strip_named_spec(%{"name" => "bash", "parameters" => parameters} = value) do
    put_in(
      value,
      ["parameters", "properties"],
      Map.delete(parameters["properties"], "retry_attempt_id")
    )
  end

  defp strip_named_spec(%{"name" => "agent_result", "parameters" => parameters} = value) do
    properties = Map.drop(parameters["properties"], ["cursor", "max_bytes", "release"])
    put_in(value, ["parameters", "properties"], properties)
  end

  defp strip_named_spec(%{"name" => "agent", "parameters" => parameters} = value) do
    put_in(
      value,
      ["parameters", "properties"],
      Map.delete(parameters["properties"], "work_item_ids")
    )
  end

  defp strip_named_spec(%{"name" => "safe_status"}), do: nil

  defp strip_named_spec(%{"name" => "plan", "parameters" => parameters} = value),
    do: %{value | "parameters" => legacy_plan_schema(parameters)}

  defp strip_named_spec(value), do: value

  defp strip_plan_schema(
         %{"Ouroboros.Provider.Native.Tools.Plan" => %{"parameters" => schema}} = value
       ),
       do:
         put_in(
           value,
           ["Ouroboros.Provider.Native.Tools.Plan", "parameters"],
           legacy_plan_schema(schema)
         )

  defp strip_plan_schema(%{"Ouroboros.Provider.Native.Tools.Plan" => schema} = value),
    do:
      Map.put(
        value,
        "Ouroboros.Provider.Native.Tools.Plan",
        cond do
          get_in(schema, ["properties", "steps", "items", "properties"]) ->
            legacy_plan_schema(schema)

          get_in(schema, ["properties", "accept"]) ->
            update_in(schema, ["properties"], &Map.delete(&1, "accept"))

          true ->
            schema
        end
      )

  defp strip_plan_schema(value), do: value

  defp legacy_plan_schema(schema) do
    schema = update_in(schema, ["properties"], &Map.delete(&1, "accept"))

    drop =
      ~w(id deliverable work_state owner_task_id criteria evidence child_settlement blocker acceptance)

    update_in(schema, ["properties", "steps", "items", "properties"], &Map.drop(&1, drop))
  end
end
