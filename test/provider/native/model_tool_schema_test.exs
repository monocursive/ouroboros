defmodule Ouroboros.Provider.Native.ModelToolSchemaTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Provider.Native.Model.ToolSchema
  alias Ouroboros.Provider.Native.Tools

  test "every static tool reaches OpenAI Responses with its required contract intact" do
    specs = Tools.specs(nil, nil)
    tools = ToolSchema.prepare(specs, "openai_codex:gpt-5.6-sol")

    assert Enum.all?(tools, & &1.strict)

    context = ReqLLM.Context.new([ReqLLM.Context.user("inspect the workspace")])

    body =
      ReqLLM.Providers.OpenAI.ResponsesAPI.build_request_body(
        context,
        "gpt-5.6-sol",
        [tools: tools],
        nil
      )

    for source <- specs do
      wire = Enum.find(body["tools"], &(&1["name"] == source.name))
      assert wire["strict"]

      wire_parameters = wire["parameters"]
      source_required = MapSet.new(source.parameters["required"] || [])
      wire_required = MapSet.new(wire_parameters["required"] || [])

      assert wire_required == MapSet.new(Map.keys(wire_parameters["properties"]))

      for {name, property} <- source.parameters["properties"] do
        if MapSet.member?(source_required, name) do
          refute accepts_null?(wire_parameters["properties"][name]),
                 "#{source.name}.#{name} was required but became nullable"
        else
          assert accepts_null?(wire_parameters["properties"][name]),
                 "#{source.name}.#{name} was optional but did not become strict-compatible"
        end

        assert is_map(property)
      end
    end

    {:ok, model} = ReqLLM.model("openai_codex:gpt-5.6-sol")
    lite = ReqLLM.Providers.OpenAICodex.ResponsesLite.apply_body(body, model)
    additional = Enum.find(lite["input"], &(&1["type"] == "additional_tools"))

    assert Enum.map(additional["tools"], & &1["name"]) == Enum.map(specs, & &1.name)
    assert Enum.all?(additional["tools"], & &1["strict"])
  end

  test "restores only nulls added for optional strict properties" do
    specs = Tools.specs(nil, nil)

    assert ToolSchema.restore_input(
             specs,
             "read",
             %{"path" => "README.md", "offset" => nil, "limit" => nil}
           ) == %{"path" => "README.md"}

    # A required null is retained so local validation can reject it rather than silently
    # turning a malformed required argument into an absent one.
    assert ToolSchema.restore_input(specs, "read", %{"path" => nil, "offset" => nil}) == %{
             "path" => nil
           }

    nullable = [
      %{
        name: "mcp__test__nullable",
        description: "nullable",
        parameters: %{
          "type" => "object",
          "properties" => %{
            "note" => %{"anyOf" => [%{"type" => "string"}, %{"type" => "null"}]}
          },
          "required" => [],
          "additionalProperties" => false
        }
      }
    ]

    assert ToolSchema.restore_input(nullable, "mcp__test__nullable", %{"note" => nil}) == %{
             "note" => nil
           }
  end

  test "keeps open MCP schemas non-strict without changing their argument surface" do
    open = %{
      name: "mcp__test__open",
      description: "Arguments are documented remotely.",
      parameters: %{"type" => "object", "additionalProperties" => true}
    }

    [tool] = ToolSchema.prepare([open], "openai_codex:gpt-5.6-sol")

    refute tool.strict
    assert tool.parameter_schema == open.parameters

    refute ToolSchema.strict_compatible?(%{
             "type" => "object",
             "properties" => %{"anything" => true},
             "additionalProperties" => false
           })

    refute ToolSchema.strict_compatible?(%{
             "type" => "object",
             "properties" => %{"query" => %{"type" => "string"}},
             "required" => ["query"]
           })
  end

  test "strictifies a closed MCP schema and preserves its required contract" do
    exact = %{
      name: "mcp__test__exact",
      description: "Search a remote index.",
      parameters: %{
        "type" => "object",
        "properties" => %{
          "query" => %{"type" => "string"},
          "limit" => %{"type" => "integer"}
        },
        "required" => ["query"],
        "additionalProperties" => false
      }
    }

    [tool] = ToolSchema.prepare([exact], "openai_codex:gpt-5.6-sol")

    assert tool.strict
    assert MapSet.new(tool.parameter_schema["required"]) == MapSet.new(["query", "limit"])
    refute accepts_null?(tool.parameter_schema["properties"]["query"])
    assert accepts_null?(tool.parameter_schema["properties"]["limit"])
  end

  test "does not impose OpenAI strict semantics on other provider transports" do
    [read] = ToolSchema.prepare(Tools.specs(["read"], nil), "anthropic:claude-sonnet-4-6")

    refute read.strict
    assert read.parameter_schema["required"] == ["path"]
  end

  test "the plan schema names and validates every nested field" do
    plan = Tools.specs(["plan"], nil) |> hd()
    item = plan.parameters["properties"]["steps"]["items"]

    assert item["required"] == ["step", "status"]
    assert Map.keys(item["properties"]) |> Enum.sort() == ["status", "step"]
    assert item["additionalProperties"] == false
  end

  defp accepts_null?(%{"type" => "null"}), do: true
  defp accepts_null?(%{"type" => types}) when is_list(types), do: "null" in types
  defp accepts_null?(%{"enum" => values}) when is_list(values), do: nil in values

  defp accepts_null?(schema) when is_map(schema) do
    Enum.any?(~w(anyOf oneOf), fn key ->
      case Map.get(schema, key) do
        variants when is_list(variants) -> Enum.any?(variants, &accepts_null?/1)
        _none -> false
      end
    end)
  end

  defp accepts_null?(_schema), do: false
end
