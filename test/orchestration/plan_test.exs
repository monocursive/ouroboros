defmodule Ouroboros.Orchestration.PlanTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Orchestration.Plan

  test "builds a serializable deterministic DAG with fan-out and fan-in" do
    assert {:ok, plan} =
             Plan.new(
               "release-42",
               [
                 %{id: "inspect", input: %{objective: "inspect the repository"}},
                 %{id: "test", dependencies: ["inspect"]},
                 %{id: "review", dependencies: ["inspect"]},
                 %{id: "merge", dependencies: ["test", "review"]}
               ],
               metadata: %{request_id: "stable-1"}
             )

    assert plan.step_order == ["inspect", "test", "review", "merge"]
    assert plan.steps["inspect"].state == :ready
    assert plan.steps["test"].state == :pending
    assert plan.steps["review"].state == :pending
    assert plan.steps["merge"].state == :pending
    assert Plan.validate(plan) == :ok
    refute contains_runtime_handle?(plan)
  end

  test "rejects unstable IDs, duplicates, missing dependencies, and cycles" do
    assert {:error, {:invalid_id, "has space"}} = Plan.new("has space", [%{id: "ok"}])

    assert {:error, {:duplicate_step_id, "same"}} =
             Plan.new("p", [%{id: "same"}, %{id: "same"}])

    assert {:error, {:unknown_dependency, "b", "missing"}} =
             Plan.new("p", [%{id: "a"}, %{id: "b", dependencies: ["missing"]}])

    assert {:error, :cyclic_dependencies} =
             Plan.new("p", [
               %{id: "a", dependencies: ["b"]},
               %{id: "b", dependencies: ["a"]}
             ])
  end

  test "builds a heterogeneous plan and defaults every step to the coding kind" do
    assert {:ok, plan} =
             Plan.new("self-improvement", [
               %{id: "write", input: %{objective: "Write the capability"}},
               %{
                 id: "build",
                 kind: :forge,
                 dependencies: ["write"],
                 input: %{
                   module: "Ouroboros.Capability.Echo",
                   source_path: "capabilities/echo.ex"
                 }
               }
             ])

    assert plan.steps["write"].kind == :coding
    assert plan.steps["build"].kind == :forge
    assert plan.steps["build"].state == :pending
    assert Plan.validate(plan) == :ok

    # A model-normalized plan arrives with string keys and a string kind. No new
    # atom is created for either.
    assert {:ok, from_json} =
             Plan.new("from-json", [
               %{
                 id: "build",
                 kind: "forge",
                 input: %{
                   "module" => "Ouroboros.Capability.Echo",
                   "source_path" => "capabilities/echo.ex"
                 }
               }
             ])

    assert from_json.steps["build"].kind == :forge
  end

  test "rejects unknown step kinds" do
    assert {:error, {:invalid_step_kind, "a", {:unknown_step_kind, :deploy}}} =
             Plan.new("p", [%{id: "a", kind: :deploy}])

    assert {:error, {:invalid_step_kind, "a", {:unknown_step_kind, "forge "}}} =
             Plan.new("p", [%{id: "a", kind: "forge "}])

    assert {:error, {:invalid_step_kind, "a", {:unknown_step_kind, false}}} =
             Plan.new("p", [%{id: "a", kind: false}])
  end

  test "holds forge steps to the capability namespace and a contained relative path" do
    assert {:error, {:invalid_step_input, "a", {:invalid_forge_input, [:module]}}} =
             Plan.new("p", [%{id: "a", kind: :forge, input: %{module: "Ouroboros.Capability.X"}}])

    assert {:error, {:invalid_step_input, "a", {:invalid_forge_input, keys}}} =
             Plan.new("p", [
               %{
                 id: "a",
                 kind: :forge,
                 input: %{
                   module: "Ouroboros.Capability.X",
                   source_path: "x.ex",
                   nodes: [:node@host]
                 }
               }
             ])

    assert keys == [:module, :nodes, :source_path]

    for module <- [
          "Ouroboros.Upgrade.Forge.Sneak",
          "Ouroboros.Control.Server",
          "Elixir.Ouroboros.Capability.X",
          "Ouroboros.Capability",
          "ouroboros.capability.x",
          :"Ouroboros.Capability.X"
        ] do
      assert {:error, {:invalid_step_input, "a", {:invalid_capability_module, ^module}}} =
               Plan.new("p", [
                 %{id: "a", kind: :forge, input: %{module: module, source_path: "x.ex"}}
               ])
    end

    for path <- [
          "../outside.ex",
          "capabilities/../../outside.ex",
          "/etc/passwd",
          "./x.ex",
          "capabilities//x.ex",
          "capabilities/",
          "",
          <<"x", 0, ".ex">>,
          :x
        ] do
      assert {:error, {:invalid_step_input, "a", {:invalid_source_path, ^path}}} =
               Plan.new("p", [
                 %{
                   id: "a",
                   kind: :forge,
                   input: %{module: "Ouroboros.Capability.X", source_path: path}
                 }
               ])
    end

    # A persisted step is held to the same schema, so a snapshot that was edited
    # under the store cannot describe work the plan API would have refused.
    {:ok, plan} =
      Plan.new("p", [
        %{
          id: "a",
          kind: :forge,
          input: %{module: "Ouroboros.Capability.X", source_path: "x.ex"}
        }
      ])

    tampered =
      put_in(plan.steps["a"].input, %{module: "Kernel", source_path: "../../etc/passwd"})

    assert {:error, {:invalid_step, "a"}} = Plan.validate(tampered)
  end

  test "rejects runtime handles nested in public plan data" do
    assert {:error, {:unserializable_input, "a"}} =
             Plan.new("p", [%{id: "a", input: %{nested: [self()]}}])

    assert {:error, :unserializable_metadata} =
             Plan.new("p", [%{id: "a"}], metadata: %{callback: fn -> :ok end})

    assert {:error, {:unserializable_input, "a"}} =
             Plan.new("p", [%{id: "a", input: [safe: :value] ++ [self() | self()]}])
  end

  test "refuses coding-step runtime policy in the durable plan" do
    assert {:error, {:invalid_step_input, "a", {:runtime_policy_not_allowed, keys}}} =
             Plan.new("p", [
               %{id: "a", input: %{objective: "write it", options: [provider: :claude]}}
             ])

    assert :options in keys
    assert :objective in keys

    assert {:error, {:invalid_step_input, "a", {:runtime_policy_not_allowed, [:worker_id]}}} =
             Plan.new("p", [%{id: "a", input: %{worker_id: "w1"}}])

    assert {:ok, _plan} = Plan.new("p", [%{id: "a", input: %{objective: "write it"}}])
    assert {:ok, _plan} = Plan.new("p", [%{id: "a"}])
  end

  defp contains_runtime_handle?(term)
       when is_pid(term) or is_reference(term) or is_port(term) or is_function(term),
       do: true

  defp contains_runtime_handle?(term) when is_list(term),
    do: Enum.any?(term, &contains_runtime_handle?/1)

  defp contains_runtime_handle?(term) when is_tuple(term) do
    term |> Tuple.to_list() |> Enum.any?(&contains_runtime_handle?/1)
  end

  defp contains_runtime_handle?(term) when is_map(term) do
    term
    |> Map.to_list()
    |> Enum.any?(fn {key, value} ->
      contains_runtime_handle?(key) or contains_runtime_handle?(value)
    end)
  end

  defp contains_runtime_handle?(_term), do: false
end
