defmodule Ouroboros.Orchestration.PlanTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Orchestration.Plan

  test "builds a serializable deterministic DAG with fan-out and fan-in" do
    assert {:ok, plan} =
             Plan.new(
               "release-42",
               [
                 %{id: "inspect", input: %{path: "."}},
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

  test "rejects runtime handles nested in public plan data" do
    assert {:error, {:unserializable_input, "a"}} =
             Plan.new("p", [%{id: "a", input: %{nested: [self()]}}])

    assert {:error, :unserializable_metadata} =
             Plan.new("p", [%{id: "a"}], metadata: %{callback: fn -> :ok end})

    assert {:error, {:unserializable_input, "a"}} =
             Plan.new("p", [%{id: "a", input: [safe: :value] ++ [self() | self()]}])
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
