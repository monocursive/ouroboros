defmodule Ouroboros.Test.NativeToolBehaviorBaseline.Probe do
  @moduledoc false
  use Jido.Action,
    name: "native_contract_probe",
    description: "Synthetic action that reports its effective input without external effects.",
    schema: [
      title: [type: :string, required: true],
      count: [type: :pos_integer, default: 2],
      enabled: [type: :boolean, default: false],
      items: [type: {:list, :any}, default: []],
      payload: [type: :any, default: nil]
    ]

  @impl true
  def run(params, context) do
    send(context.observer, {:effective_input, params})
    {:ok, %{output: "synthetic effect"}}
  end
end

defmodule Ouroboros.Test.NativeToolBehaviorBaseline do
  @moduledoc false
  alias Ouroboros.Provider.Native.Model.ToolSchema
  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Test.NativeToolBehaviorBaseline.Probe

  def with_context(fun) do
    directory =
      Path.join(System.tmp_dir!(), "native-behavior-#{System.unique_integer([:positive])}")

    keys = [:audit, :native_user_skills_dir]
    previous = Map.new(keys, &{&1, Application.fetch_env(:ouroboros, &1)})
    File.mkdir_p!(directory)
    Application.put_env(:ouroboros, :audit, mode: :standard)
    Application.put_env(:ouroboros, :native_user_skills_dir, directory)

    try do
      fun.()
    after
      Enum.each(previous, fn
        {key, {:ok, value}} -> Application.put_env(:ouroboros, key, value)
        {key, :error} -> Application.delete_env(:ouroboros, key)
      end)

      File.rm_rf!(directory)
    end
  end

  def specs do
    modules = Tools.modules() ++ [Tools.Capability, Tools.Forge, Probe]
    Enum.map(modules, &Tools.spec(&1, distributed: false)) ++ mcp_specs()
  end

  def mcp_specs do
    [
      %{
        name: "mcp__baseline__open",
        description: "The remote server accepts arbitrary arguments.",
        parameters: %{"type" => "object", "additionalProperties" => true}
      },
      %{
        name: "mcp__baseline__nested",
        description: "A controlled remote nested and nullable contract.",
        parameters: %{
          "type" => "object",
          "properties" => %{
            "rows" => %{
              "type" => "array",
              "items" => %{
                "type" => "object",
                "properties" => %{
                  "id" => %{"type" => "integer", "minimum" => 1, "maximum" => 3},
                  "note" => %{"type" => ["string", "null"]},
                  "label" => %{"type" => "string"}
                },
                "required" => ["id"],
                "additionalProperties" => false
              }
            },
            "options" => %{
              "anyOf" => [
                %{
                  "type" => "object",
                  "properties" => %{"enabled" => %{"type" => "boolean"}},
                  "required" => [],
                  "additionalProperties" => false
                },
                %{"type" => "null"}
              ]
            }
          },
          "required" => ["rows"],
          "additionalProperties" => false
        }
      }
    ]
  end

  # Inline metadata avoids the host's model catalogue, account configuration and network.
  def models do
    [
      {"responses", model(:openai, "openai_responses", false)},
      {"responses_lite", model(:openai_codex, "openai_codex_responses", true)},
      {"other_transport", model(:anthropic, "anthropic_messages", false)}
    ]
  end

  defp model(provider, protocol, lite) do
    %{
      provider: provider,
      id: "native-parity-fixture",
      name: "Native parity fixture",
      extra: %{wire: %{protocol: protocol}, use_responses_lite: lite}
    }
  end

  def validation_cases do
    [
      {"missing_required", "read", %{}},
      {"wrong_primitive", "read", %{"path" => 7}},
      {"required_null", "read", %{"path" => nil}},
      {"optional_null", "read", %{"path" => "README.md", "offset" => nil}},
      {"omitted_defaults", "read", %{"path" => "README.md"}},
      {"integer_minimum", "read", %{"path" => "README.md", "offset" => 0}},
      {"integer_below_minimum", "read", %{"path" => "README.md", "offset" => -1}},
      {"integer_fraction", "read", %{"path" => "README.md", "offset" => 1.5}},
      {"unknown_key", "read", %{"path" => "README.md", "hallucinated" => true}},
      {"atom_key_only", "read", %{path: "README.md"}},
      {"atom_string_collision", "read", %{"path" => "string", :path => "atom"}},
      {"atom_string_collision_wrong_type", "read", %{"path" => 1, :path => "atom"}},
      {"empty_optional", "ls", %{}},
      {"positive_integer_zero", "ls", %{"depth" => 0}},
      {"positive_integer_one", "ls", %{"depth" => 1}},
      {"positive_integer_large", "ls", %{"depth" => 1000}},
      {"wrong_boolean", "edit",
       %{"path" => "a", "old_string" => "x", "new_string" => "y", "replace_all" => "true"}},
      {"not_object_array", "read", []},
      {"not_object_string", "read", "README.md"},
      {"not_object_null", "read", nil},
      {"not_advertised", "invented", %{}},
      {"alias_plan", "todo", %{"steps" => []}},
      {"plan_empty_array", "plan", %{"steps" => []}},
      {"plan_nested_valid", "plan", %{"steps" => [%{"step" => "Review", "status" => "pending"}]}},
      {"plan_nested_missing", "plan", %{"steps" => [%{"step" => "Review"}]}},
      {"plan_nested_wrong_primitive", "plan", %{"steps" => ["Review"]}},
      {"plan_nested_unknown", "plan",
       %{"steps" => [%{"step" => "Review", "status" => "pending", "extra" => true}]}},
      {"plan_nested_bad_enum", "plan",
       %{"steps" => [%{"step" => "Review", "status" => "later"}]}},
      {"agent_valid", "agent", %{"prompt" => "Inspect", "tools" => ["read"]}},
      {"agent_tools_wrong_item", "agent", %{"prompt" => "Inspect", "tools" => [1]}},
      {"agent_default_omission", "agent", %{"prompt" => "Inspect"}},
      {"agent_max_turns_zero", "agent", %{"prompt" => "Inspect", "max_turns" => 0}},
      {"capability_open_message", "capability",
       %{
         "operation" => "call",
         "name" => "fixture",
         "message" => %{"rows" => [%{"anything" => [1, true, nil]}]}
       }},
      {"capability_wrong_message", "capability", %{"operation" => "call", "message" => "{}"}},
      {"capability_null_message", "capability", %{"operation" => "call", "message" => nil}},
      {"capability_bad_enum", "capability", %{"operation" => "delete"}},
      {"forge_open_eval", "forge",
       %{
         "operation" => "forge",
         "eval" => %{"probes" => [%{"input" => %{"a" => 1}}], "future" => true}
       }},
      {"forge_wrong_eval", "forge", %{"operation" => "forge", "eval" => "{}"}},
      {"forge_bad_enum", "forge", %{"operation" => "build"}},
      {"forge_unknown_author", "forge", %{"operation" => "status", "author" => "model"}},
      {"mcp_open", "mcp__baseline__open", %{"arbitrary" => [%{"deep" => nil}]}},
      {"mcp_nested_valid", "mcp__baseline__nested",
       %{"rows" => [%{"id" => 1, "note" => nil}, %{"id" => 3}]}},
      {"mcp_nested_below_bound", "mcp__baseline__nested", %{"rows" => [%{"id" => 0}]}},
      {"mcp_nested_above_bound", "mcp__baseline__nested", %{"rows" => [%{"id" => 4}]}},
      {"mcp_nested_unknown", "mcp__baseline__nested",
       %{"rows" => [%{"id" => 1, "unknown" => true}]}},
      {"mcp_nested_null_required", "mcp__baseline__nested", %{"rows" => [%{"id" => nil}]}},
      {"mcp_nested_wrong_boolean", "mcp__baseline__nested",
       %{"rows" => [], "options" => %{"enabled" => "yes"}}}
    ]
  end

  def action_cases do
    [
      {"defaults", %{"title" => "Inspect"}},
      {"explicit_values", %{"title" => "Inspect", "count" => 3, "enabled" => true}},
      {"null_any", %{"title" => "Inspect", "payload" => nil}},
      {"nested_string_keys",
       %{
         "title" => "Inspect",
         "items" => [%{"id" => 1, "nested" => [nil, true]}],
         "payload" => %{"name" => "untouched"}
       }},
      {"unknown_keys_dropped", %{"title" => "Inspect", "unregistered_field" => "ignored"}},
      {"atom_string_collision", %{"title" => "string", :title => "atom", :count => 9}},
      {"atom_only_ignored", %{title: "atom"}},
      {"required_missing", %{}},
      {"required_null", %{"title" => nil}},
      {"optional_null", %{"title" => "Inspect", "count" => nil}},
      {"wrong_primitive", %{"title" => "Inspect", "enabled" => "true"}},
      {"below_bound", %{"title" => "Inspect", "count" => 0}},
      {"wrong_array", %{"title" => "Inspect", "items" => %{}}}
    ]
  end

  def restoration_cases do
    [
      {"optional_read_nulls", "read", %{"path" => "README.md", "offset" => nil, "limit" => nil}},
      {"required_read_null", "read", %{"path" => nil, "offset" => nil}},
      {"plan_nested", "plan",
       %{"steps" => [%{"step" => "Inspect", "status" => nil}], "explanation" => nil}},
      {"agent_defaults", "agent",
       %{"prompt" => "Inspect", "tools" => nil, "worktree" => nil, "max_turns" => nil}},
      {"capability_open_message", "capability",
       %{"operation" => "call", "name" => nil, "message" => %{"keep_null" => nil}}},
      {"forge_open_eval", "forge",
       %{"operation" => "forge", "eval" => %{"keep_null" => nil}, "path" => nil}},
      {"mcp_nested_nulls", "mcp__baseline__nested",
       %{
         "rows" => [%{"id" => 1, "note" => nil, "label" => nil}, %{"id" => nil, "label" => nil}],
         "options" => %{"enabled" => nil}
       }},
      {"mcp_nullable_union", "mcp__baseline__nested", %{"rows" => [], "options" => nil}},
      {"mcp_open_nulls", "mcp__baseline__open", %{"keep_null" => nil}},
      {"unknown_tool", "invented", %{"keep_null" => nil}},
      {"non_object", "read", nil}
    ]
  end

  def capture do
    specs = specs()

    %{
      validation:
        Enum.map(validation_cases(), fn {id, name, input} ->
          %{id: id, name: name, input: input, result: Tools.validate_call(name, input, specs)}
        end),
      action:
        Enum.map(action_cases(), fn {id, input} ->
          %{id: id, input: input, observation: observe_action(input)}
        end),
      transport:
        Enum.map(models(), fn {id, model} ->
          tools = ToolSchema.prepare(specs, model)

          %{
            id: id,
            model: model,
            tools:
              Enum.map(tools, &Map.take(&1, [:name, :description, :parameter_schema, :strict]))
          }
        end),
      restoration:
        Enum.map(restoration_cases(), fn {id, name, input} ->
          %{
            id: id,
            name: name,
            input: input,
            restored: ToolSchema.restore_input(specs, name, input)
          }
        end)
    }
  end

  def observe_action(input) do
    result = Tools.execute(Probe, input, %{observer: self()}, 5_000)

    effective_input =
      receive do
        {:effective_input, params} -> {:received, params}
      after
        0 -> :no_effect
      end

    %{result: result, effective_input: effective_input}
  end
end
