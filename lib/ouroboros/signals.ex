defmodule Ouroboros.Signals.AgentMessage do
  @moduledoc "A typed point-to-point message between logical agents."

  use Jido.Signal,
    type: "ouroboros.agent.message",
    default_source: "/ouroboros/mesh",
    schema: [
      from: [type: :string, required: true],
      body: [type: :any, required: true],
      correlation_id: [type: :string, required: true],
      causation_id: [type: :any, default: nil]
    ]
end

defmodule Ouroboros.Signals.TaskAssigned do
  @moduledoc "A typed task assignment sent to a worker agent."

  use Jido.Signal,
    type: "ouroboros.agent.task.assigned",
    default_source: "/ouroboros/mesh",
    schema: [
      from: [type: :string, required: true],
      task_id: [type: :string, required: true],
      objective: [type: :string, required: true],
      correlation_id: [type: :string, required: true]
    ]
end

defmodule Ouroboros.Signals.TaskCompleted do
  @moduledoc "Marks an agent's current task complete."

  use Jido.Signal,
    type: "ouroboros.agent.task.completed",
    default_source: "/ouroboros/mesh",
    schema: [
      task_id: [type: :string, required: true],
      result: [type: :any, required: true]
    ]
end
