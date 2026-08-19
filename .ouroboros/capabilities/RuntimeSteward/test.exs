defmodule Ouroboros.Capability.RuntimeStewardTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Agent.Worker.{AssignTask, CompleteTask, ReceiveMessage}
  alias Ouroboros.Capability.RuntimeSteward

  test "starts with bounded improvement defaults and no effect routes" do
    agent = RuntimeSteward.new()

    assert agent.state.role == "runtime-steward"
    assert agent.state.status == :idle
    assert agent.state.messages_received == 0

    routes = RuntimeSteward.signal_routes()

    assert {"ouroboros.agent.message", ReceiveMessage} in routes

    refute Enum.any?(routes, fn {type, _action} ->
             String.starts_with?(type, "ouroboros.agent.effect.")
           end)
  end

  test "its schema retains improvement evidence in arrival order" do
    agent = RuntimeSteward.new()
    first = %{kind: "improvement_observation", summary: "Preserve operator authority"}

    assert {:ok, first_update} =
             ReceiveMessage.run(
               %{
                 from: "operator",
                 body: first,
                 correlation_id: "runtime-steward-test-1",
                 causation_id: nil
               },
               %{agent: agent}
             )

    agent = %{agent | state: Map.merge(agent.state, first_update)}
    second = %{kind: "improvement_observation", summary: "Keep changes measurable"}

    assert {:ok, second_update} =
             ReceiveMessage.run(
               %{
                 from: "operator",
                 body: second,
                 correlation_id: "runtime-steward-test-2",
                 causation_id: "runtime-steward-test-1"
               },
               %{agent: agent}
             )

    assert second_update.messages_received == 2
    assert second_update.last_message.body == second
    assert Enum.map(second_update.inbox, & &1.body) == [first, second]
  end

  test "its schema supports the existing assignment lifecycle" do
    agent = RuntimeSteward.new()

    assert {:ok, assigned} =
             AssignTask.run(
               %{
                 from: "operator",
                 task_id: "improvement-1",
                 objective: "Verify one bounded improvement",
                 correlation_id: "runtime-steward-assignment"
               },
               %{agent: agent}
             )

    assert assigned.status == :working
    assert assigned.current_task == "improvement-1"

    agent = %{agent | state: Map.merge(agent.state, assigned)}

    assert {:ok, completed} =
             CompleteTask.run(
               %{task_id: "improvement-1", result: %{verified: true}},
               %{agent: agent}
             )

    assert completed == %{status: :completed, last_answer: %{verified: true}}
  end
end
