defmodule Ouroboros.NativeToolSchemaBaseline do
  @moduledoc false

  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Upgrade.Rollout.Registry, as: RolloutRegistry

  defmodule Empty do
    def name, do: "baseline_empty"
    def description, do: "An empty action schema."
    def schema, do: []
  end

  defmodule Nested do
    def name, do: "baseline_nested"
    def description, do: "Nested objects, arrays, open objects and schema-valued extra keys."

    def schema do
      %{
        "type" => "object",
        "properties" => %{
          "open" => %{"type" => "object", "properties" => %{}, "additionalProperties" => true},
          "dictionary" => %{
            "type" => "object",
            "properties" => %{},
            "additionalProperties" => %{"type" => "object", "properties" => %{}}
          },
          "rows" => %{
            "type" => "array",
            "items" => %{
              "type" => "object",
              "properties" => %{"value" => %{"type" => ["string", "null"]}},
              "required" => ["value"]
            }
          },
          "choice" => %{
            "anyOf" => [
              %{"properties" => %{"label" => %{"type" => "string"}}},
              %{"type" => "null"}
            ]
          },
          "closed" => %{"type" => "object", "additionalProperties" => false}
        },
        "required" => ["rows"],
        "additionalProperties" => true,
        "allOf" => [%{"properties" => %{"count" => %{"type" => "integer", "minimum" => 1}}}]
      }
    end
  end

  defmodule Strict do
    def name, do: "baseline_strict"
    def description, do: "The optional strict callback overrides explicitly open typed objects."
    def strict?, do: true
    def schema, do: Ouroboros.NativeToolSchemaBaseline.Nested.schema()
  end

  defmodule NonStrict do
    def name, do: "baseline_non_strict"
    def description, do: "An explicit false strict callback preserves open objects."
    def strict?, do: false
    def schema, do: Ouroboros.NativeToolSchemaBaseline.Nested.schema()
  end

  defmodule Defaults do
    def name, do: "baseline_defaults"
    def description, do: "Keyword schema defaults, enums, bounds and lists."

    def schema do
      [
        title: [type: :string, required: true, doc: "The title."],
        count: [type: :pos_integer, default: 2, doc: "A positive count."],
        offset: [type: :non_neg_integer, default: 0],
        enabled: [type: :boolean, default: false],
        labels: [type: {:list, :string}, default: []],
        mode: [type: {:in, ["fast", "careful"]}, default: "careful"],
        payload: [type: :any, default: nil]
      ]
    end
  end

  defmodule DescriptionOverride do
    def name, do: "baseline_description_override"
    def description, do: "Static fallback description."
    def schema, do: []
    def description(opts), do: Keyword.fetch!(opts, :description)
  end

  # The fixture pool implements only the two read messages used by Mcp.specs/2. No
  # configured process, command, network connection or handshake can run here.
  defmodule McpPool do
    use GenServer
    def init(state), do: {:ok, state}
    def handle_call({:ensure, _root, []}, _from, state), do: {:reply, [], state}
    def handle_call({:tools, _root}, _from, state), do: {:reply, state, state}
  end

  defmodule RegistryFixture do
    use GenServer
    def init(state), do: {:ok, state}
    def handle_call(:list, _from, state), do: {:reply, Map.values(state.rollouts), state}
  end

  def action_modules, do: Tools.modules() ++ [Tools.Capability, Tools.Forge]
  def edge_modules, do: [Empty, Nested, Strict, NonStrict, Defaults, DescriptionOverride]
  def all_modules, do: action_modules() ++ edge_modules()

  def contexts do
    [
      {"fleet_hidden", nil, nil, [distributed: false], false, false, :standard},
      {"fleet_visible", [], [], [distributed: true], false, false, :standard},
      {"depth_restricted", nil, nil, [distributed: true, subagent_depth: 2], false, false,
       :standard},
      {"allow_and_deny", [" read ", "plan", "agent", "fleet", "skill", "bash"], ["agent", "bash"],
       [distributed: true], false, false, :standard},
      {"skills_budget", ["skill"], nil, [context_window: 1_000], false, false, :standard},
      {"dynamic", nil, nil, [distributed: true], true, true, :standard},
      {"dynamic_filtered", ["capability", "forge", "mcp__fixture__open", "mcp__fixture__nested"],
       ["forge", "mcp__fixture__nested"], [distributed: false], true, true, :standard},
      {"mcp_deferred", ["mcp__fixture__open", "mcp__fixture__nested"], nil,
       [max_tool_schema_bytes: 1], false, true, :standard},
      {"required_audit", nil, nil, [distributed: true], true, true, :required}
    ]
  end

  def context_inputs do
    Enum.map(contexts(), fn {id, allowed, disallowed, opts, capability, mcp, audit} ->
      %{
        id: id,
        allowed: allowed,
        disallowed: disallowed,
        options: Map.new(opts),
        capability_live: capability,
        forge_enabled: capability,
        mcp_enabled: mcp,
        audit_mode: audit
      }
    end)
  end

  def composed_specs(context) do
    Map.new(contexts(), fn {id, allowed, disallowed, opts, capability, mcp, audit} ->
      Application.put_env(:ouroboros, :audit, mode: audit, root: context.audit_root)
      Application.put_env(:ouroboros, :native_forge_tool, capability)
      Application.put_env(:ouroboros, :mcp, enabled: mcp)
      :sys.replace_state(RolloutRegistry, &Map.put(&1, :rollouts, rollouts(capability)))

      {id, Tools.specs(allowed, disallowed, Keyword.merge(context.options, opts))}
    end)
  end

  def description_specs do
    Map.new(
      [
        {"overridden", [description: "Session description."]},
        {"empty", [description: ""]},
        {"nil", [description: nil]},
        {"raises", []}
      ],
      fn {id, opts} -> {id, Tools.spec(DescriptionOverride, opts)} end
    )
  end

  def with_context(fun) do
    keys = [
      :audit,
      :native_forge_tool,
      :native_user_skills_dir,
      :mcp,
      :mcp_servers,
      :mcp_user_path
    ]

    previous = Map.new(keys, &{&1, Application.fetch_env(:ouroboros, &1)})

    root =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-schema-baseline-#{System.unique_integer([:positive])}"
      )

    workspace = Path.join(root, "workspace")
    user_skills = Path.join(root, "user-skills")
    File.mkdir_p!(workspace)
    File.mkdir_p!(user_skills)

    write_skill(
      Path.join(workspace, ".agents/skills/alpha"),
      "alpha",
      "Inspect deterministic fixtures."
    )

    write_skill(
      Path.join(workspace, ".agents/skills/zeta"),
      "zeta",
      String.duplicate("A bounded description. ", 12)
    )

    write_skill(Path.join(user_skills, "alpha"), "alpha", "Shadowed by the project skill.")
    write_skill(Path.join(user_skills, "beta"), "beta", "Explain schema and transport contracts.")

    Application.put_env(:ouroboros, :audit, mode: :standard)
    Application.put_env(:ouroboros, :native_forge_tool, false)
    Application.put_env(:ouroboros, :native_user_skills_dir, user_skills)
    Application.put_env(:ouroboros, :mcp, enabled: false)
    Application.put_env(:ouroboros, :mcp_servers, %{})
    Application.put_env(:ouroboros, :mcp_user_path, Path.join(root, "absent-mcp.json"))
    {:ok, pool} = GenServer.start_link(McpPool, mcp_tools())
    registry = registry_fixture()

    try do
      fun.(%{
        options: [workspace: workspace, context_window: 8_000, pool: pool, distributed: false],
        audit_root: Path.join(root, "audit")
      })
    after
      restore_registry(registry)
      GenServer.stop(pool)

      Enum.each(previous, fn
        {key, {:ok, value}} -> Application.put_env(:ouroboros, key, value)
        {key, :error} -> Application.delete_env(:ouroboros, key)
      end)

      File.rm_rf!(root)
    end
  end

  def json(term), do: term |> JSON.encode!() |> JSON.decode!()

  defp registry_fixture do
    case Process.whereis(RolloutRegistry) do
      nil ->
        {:ok, pid} =
          GenServer.start_link(RegistryFixture, %{rollouts: %{}}, name: RolloutRegistry)

        {:owned, pid}

      pid ->
        previous = :sys.get_state(pid)
        :sys.replace_state(pid, &Map.put(&1, :rollouts, %{}))
        {:borrowed, pid, previous}
    end
  end

  defp restore_registry({:owned, pid}), do: GenServer.stop(pid)

  defp restore_registry({:borrowed, pid, previous}),
    do: :sys.replace_state(pid, fn _ -> previous end)

  defp rollouts(false), do: %{}

  defp rollouts(true) do
    %{
      "schema-baseline" => %{
        artifact_id: "schema-baseline",
        module: "wasm/schema-baseline",
        state: :live,
        epoch: 1,
        component_sha256: String.duplicate("a", 64),
        nodes: [node()],
        created_at: 0
      }
    }
  end

  defp mcp_tools do
    [
      {"fixture",
       [
         %{
           name: "open",
           description: "An explicitly open MCP object.",
           input_schema: %{
             "type" => "object",
             "properties" => %{},
             "additionalProperties" => true
           }
         },
         %{
           name: "nested",
           description: "An exact MCP nested schema.",
           input_schema: Nested.schema()
         }
       ]}
    ]
  end

  defp write_skill(dir, name, description) do
    File.mkdir_p!(dir)

    File.write!(
      Path.join(dir, "SKILL.md"),
      "---\nname: #{name}\ndescription: #{description}\n---\nSynthetic baseline instructions.\n"
    )
  end
end
