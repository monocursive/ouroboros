defmodule Ouroboros.Provider.Native.WorkItemTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Provider.Native.WorkItem
  alias Ouroboros.Provider.Native.Tools.Plan

  describe "normalize_step/1" do
    test "normalizes a legacy plan step and derives a stable bounded id" do
      assert {:ok, first} =
               WorkItem.normalize_step(%{
                 "step" => "  implement parser  ",
                 "status" => "completed"
               })

      assert {:ok, second} =
               WorkItem.normalize_step(%{step: "implement parser", status: :completed})

      assert first == second
      assert first["step"] == "implement parser"
      assert first["status"] == "completed"
      assert first["deliverable"] == "implementation"
      assert first["work_state"] == "change_proposed"
      assert first["child_settlement"] == "unsettled"
      assert first["criteria"] == []
      assert first["evidence"] == []
      assert byte_size(first["id"]) <= 64
      refute first["work_state"] == "accepted"
    end

    test "normalizes typed additive fields and a blocker" do
      step = %{
        "id" => "WI:parser-1",
        "step" => "Understand parser failures",
        "status" => "pending",
        "deliverable" => "analysis",
        "work_state" => "blocked",
        "owner_task_id" => "task:parent-1",
        "criteria" => ["Names the failing branch"],
        "evidence" => ["test/output.log#L12"],
        "child_settlement" => "completed",
        "blocker" => %{
          "type" => "missing_input",
          "resolvable_by_parent" => true,
          "detail" => "Need the production sample"
        }
      }

      assert {:ok, item} = WorkItem.normalize_step(step)
      assert item["deliverable"] == "analysis"
      assert item["work_state"] == "blocked"
      assert item["owner_task_id"] == "task:parent-1"
      assert item["child_settlement"] == "completed"
      assert item["blocker"]["type"] == "missing_input"
    end

    test "rejects malformed, null, oversized, conflicting, and unknown fields" do
      assert {:error, {:step, :invalid}} = WorkItem.normalize_step("not a map")
      assert {:error, {:step, :invalid}} = WorkItem.normalize_step(%{"step" => nil})

      assert {:error, {:step, :too_large}} =
               WorkItem.normalize_step(%{"step" => String.duplicate("x", 201)})

      assert {:error, {:step, :conflicting}} =
               WorkItem.normalize_step(%{"step" => "one", :step => "two"})

      assert {:error, {:fields, :unknown}} =
               WorkItem.normalize_step(%{"step" => "one", "acceptance" => %{"actor" => "model"}})

      assert {:error, {:deliverable, :invalid}} =
               WorkItem.normalize_step(%{"step" => "one", "deliverable" => "deployment"})
    end

    test "rejects conflicting lifecycle and blocker combinations" do
      assert {:error, {:status, :conflicting}} =
               WorkItem.normalize_step(%{
                 "step" => "one",
                 "status" => "completed",
                 "work_state" => "investigating"
               })

      assert {:error, {:blocker, :required}} =
               WorkItem.normalize_step(%{
                 "step" => "one",
                 "status" => "pending",
                 "work_state" => "blocked"
               })

      assert {:error, {:blocker, :conflicting}} =
               WorkItem.normalize_step(%{
                 "step" => "one",
                 "blocker" => %{"type" => "other", "resolvable_by_parent" => false}
               })

      assert {:error, {:work_state, :invalid}} =
               WorkItem.normalize_step(%{
                 "step" => "one",
                 "status" => "completed",
                 "work_state" => "accepted"
               })
    end

    test "bounds references, criteria, owners, and blocker details" do
      assert {:error, {:evidence, :too_many}} =
               WorkItem.normalize_step(%{
                 "step" => "one",
                 "evidence" => List.duplicate("ref", 17)
               })

      assert {:error, {:criteria, :too_large}} =
               WorkItem.normalize_step(%{
                 "step" => "one",
                 "criteria" => [String.duplicate("x", 501)]
               })

      assert {:error, {:owner_task_id, :too_large}} =
               WorkItem.normalize_step(%{
                 "step" => "one",
                 "owner_task_id" => String.duplicate("x", 129)
               })

      assert {:error, {:blocker, :too_large}} =
               WorkItem.normalize_step(%{
                 "step" => "one",
                 "status" => "pending",
                 "work_state" => "blocked",
                 "blocker" => %{
                   "type" => "other",
                   "resolvable_by_parent" => false,
                   "detail" => String.duplicate("x", 501)
                 }
               })
    end

    test "does not create atoms from untrusted keys or enum values" do
      key = "unknown_key_#{System.unique_integer([:positive])}"
      value = "unknown_state_#{System.unique_integer([:positive])}"
      assert_raise ArgumentError, fn -> String.to_existing_atom(key) end
      assert_raise ArgumentError, fn -> String.to_existing_atom(value) end

      assert {:error, {:fields, :unknown}} =
               WorkItem.normalize_step(%{"step" => "one", key => "x"})

      assert {:error, {:work_state, :invalid}} =
               WorkItem.normalize_step(%{"step" => "one", "work_state" => value})

      assert_raise ArgumentError, fn -> String.to_existing_atom(key) end
      assert_raise ArgumentError, fn -> String.to_existing_atom(value) end
    end
  end

  describe "accept/3" do
    test "requires caller-supplied actor, criteria, and evidence" do
      item = %{
        "step" => "Review the design",
        "status" => "in_progress",
        "deliverable" => "analysis",
        "work_state" => "reviewing",
        "criteria" => ["Findings are supported by source references"],
        "evidence" => ["stale-ref"]
      }

      assert {:error, {:acceptance_actor, :empty}} = WorkItem.accept(item, " ", ["review.md"])
      assert {:error, {:evidence, :required}} = WorkItem.accept(item, "task:parent", [])

      assert {:error, {:criteria, :required}} =
               WorkItem.accept(Map.put(item, "criteria", []), "task:parent", ["review.md"])

      assert {:ok, accepted} = WorkItem.accept(item, "task:parent", ["review.md#finding-1"])
      assert accepted["status"] == "completed"
      assert accepted["work_state"] == "accepted"

      assert accepted["acceptance"] == %{
               "actor" => "task:parent",
               "decision_source" => "parent_model",
               "basis" => "model_judgment",
               "evidence_validation" => "unchecked_references",
               "deterministic" => false
             }

      assert accepted["evidence"] == ["review.md#finding-1"]
    end

    test "child settlement remains distinct from deliverable acceptance" do
      settled = %{
        "step" => "Implement parser",
        "status" => "completed",
        "work_state" => "change_proposed",
        "child_settlement" => "completed",
        "criteria" => ["Focused test passes"]
      }

      assert {:ok, item} = WorkItem.normalize_step(settled)
      refute item["work_state"] == "accepted"

      assert {:ok, accepted} = WorkItem.accept(item, "task:parent", ["ci://run/42"])
      assert accepted["child_settlement"] == "completed"
      assert accepted["work_state"] == "accepted"
    end

    test "rejects model-authored acceptance and bounds trusted acceptance inputs" do
      item = %{"step" => "one", "criteria" => ["done"]}

      assert {:error, {:fields, :unknown}} =
               WorkItem.accept(Map.put(item, "acceptance_actor", "model"), "parent", ["ref"])

      assert {:error, {:acceptance_actor, :too_large}} =
               WorkItem.accept(item, String.duplicate("x", 129), ["ref"])

      assert {:error, {:evidence, :too_large}} =
               WorkItem.accept(item, "parent", [String.duplicate("x", 513)])
    end

    test "accepted items replay only from exact authoritative parent state" do
      item = %{
        "id" => "analysis-1",
        "step" => "Review evidence",
        "status" => "in_progress",
        "deliverable" => "analysis",
        "work_state" => "reviewing",
        "criteria" => ["Report retained"],
        "evidence" => ["review.md"]
      }

      assert {:ok, first} =
               Plan.run(%{steps: [item], accept: ["analysis-1"], explanation: ""}, %{
                 principal: "parent"
               })

      [accepted] = first.plan["plan"]

      assert {:ok, replayed} =
               Plan.run(%{steps: [accepted], accept: [], explanation: ""}, %{
                 principal: "parent",
                 current_plan: first.plan
               })

      assert replayed.plan == first.plan
      forged = put_in(accepted["acceptance"]["actor"], "foreign")

      assert {:ok, %{is_error: true, output: output}} =
               Plan.run(%{steps: [forged], accept: [], explanation: ""}, %{
                 principal: "parent",
                 current_plan: first.plan
               })

      assert output =~ "untrusted_replay"
    end

    test "owned acceptance requires an exact durable item binding and terminal receipt" do
      item = %{
        "id" => "analysis-1",
        "step" => "Review evidence",
        "status" => "in_progress",
        "deliverable" => "analysis",
        "work_state" => "reviewing",
        "owner_task_id" => "sub-a",
        "criteria" => ["Report retained"],
        "evidence" => ["review.md"]
      }

      digest = WorkItem.authority_digest(item, "native-parent")

      receipt = %{
        "task_id" => "sub-a",
        "parent_session" => "native-parent",
        "item_id" => "analysis-1",
        "binding_digest" => digest,
        "settlement" => "completed",
        "outcome_digest" => String.duplicate("a", 64)
      }

      authority = %{
        "analysis-1" => %{
          "item_id" => "analysis-1",
          "task_id" => "sub-a",
          "digest" => digest,
          "state" => "settled",
          "receipt" => receipt
        }
      }

      context = %{
        principal: "parent-model",
        provider_session_id: "native-parent",
        current_plan: %{"plan" => [item], "authority" => authority}
      }

      assert {:ok, %{is_error: false, plan: plan}} =
               Plan.run(%{steps: [item], accept: ["analysis-1"], explanation: ""}, context)

      assert hd(plan["plan"])["child_settlement"] == "completed"
      assert hd(plan["plan"])["work_state"] == "accepted"

      cross_item = %{item | "id" => "analysis-2"}

      assert {:ok, %{is_error: true, output: mismatch}} =
               Plan.run(%{steps: [cross_item], accept: ["analysis-2"], explanation: ""}, context)

      assert mismatch =~ "foreign_owner"

      forged =
        put_in(
          context,
          [:current_plan, "authority", "analysis-1", "receipt", "binding_digest"],
          String.duplicate("0", 64)
        )

      assert {:ok, %{is_error: true, output: forged_output}} =
               Plan.run(%{steps: [item], accept: ["analysis-1"], explanation: ""}, forged)

      assert forged_output =~ "owner_item_mismatch"
    end

    test "plan refuses duplicate IDs and oversized replacement or acceptance lists" do
      item = %{
        "id" => "same",
        "step" => "One",
        "criteria" => ["done"],
        "evidence" => ["receipt"]
      }

      assert {:ok, %{is_error: true, output: duplicate}} =
               Plan.run(
                 %{steps: [item, %{item | "step" => "Two"}], accept: [], explanation: ""},
                 %{}
               )

      assert duplicate =~ "duplicate"

      assert {:ok, %{is_error: true, output: too_many}} =
               Plan.run(
                 %{
                   steps: Enum.map(1..41, &%{"step" => "Step #{&1}"}),
                   accept: [],
                   explanation: ""
                 },
                 %{}
               )

      assert too_many =~ "too_many"

      assert {:ok, %{is_error: true, output: invalid_accept}} =
               Plan.run(
                 %{
                   steps: [item],
                   accept: Enum.map(1..41, &"id-#{&1}"),
                   explanation: ""
                 },
                 %{}
               )

      assert invalid_accept =~ "invalid"
    end
  end
end
