defmodule Ouroboros.Capability.RuntimeSteward do
  @moduledoc """
  An inspectable mesh role for bounded Ouroboros improvement work.

  The steward can receive evidence and participate in the existing assignment
  lifecycle. It deliberately exposes no effect routes: loading this capability does
  not grant authority to start agents, delegate work, forge code, or deploy it.
  """

  @vsn 1

  use Jido.Agent,
    name: "ouroboros_runtime_steward",
    description: "Tracks evidence and assignments for bounded runtime improvements",
    schema: [
      role: [type: :string, default: "runtime-steward"],
      objective: [
        type: :any,
        default: "Improve Ouroboros through evidence-backed, operator-admitted changes"
      ],
      status: [type: :atom, default: :idle],
      parent_id: [type: :any, default: nil],
      current_task: [type: :any, default: nil],
      inbox: [type: :list, default: []],
      messages_received: [type: :non_neg_integer, default: 0],
      last_message: [type: :any, default: nil],
      last_answer: [type: :any, default: nil],
      error: [type: :any, default: nil]
    ],
    signal_routes: [
      {"ouroboros.agent.message", Ouroboros.Agent.Worker.ReceiveMessage},
      {"ouroboros.agent.task.assigned", Ouroboros.Agent.Worker.AssignTask},
      {"ouroboros.agent.task.completed", Ouroboros.Agent.Worker.CompleteTask}
    ]
end
