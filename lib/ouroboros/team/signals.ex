defmodule Ouroboros.Team.Signals.TeamStarted do
  @moduledoc "Initializes the inspectable Jido coordinator for one team."

  use Jido.Signal,
    type: "ouroboros.team.started",
    default_source: "/ouroboros/team",
    schema: [
      team_id: [type: :string, required: true],
      coordinator_id: [type: :string, required: true]
    ]
end

defmodule Ouroboros.Team.Signals.WorkerAdded do
  @moduledoc "Records a local or distributed worker in the team coordinator."

  use Jido.Signal,
    type: "ouroboros.team.worker.added",
    default_source: "/ouroboros/team",
    schema: [
      worker_id: [type: :string, required: true],
      worker_node: [type: :string, required: true],
      role: [type: :string, required: true],
      hierarchy: [type: :atom, required: true]
    ]
end

defmodule Ouroboros.Team.Signals.TaskDelegated do
  @moduledoc "Records that a worker owns a provider-neutral coding task."

  use Jido.Signal,
    type: "ouroboros.team.task.delegated",
    default_source: "/ouroboros/team",
    schema: [
      delegation_id: [type: :string, required: true],
      worker_id: [type: :string, required: true],
      objective: [type: :string, required: true],
      coding_task_id: [type: :string, required: true],
      coding_node: [type: :string, required: true]
    ]
end

defmodule Ouroboros.Team.Signals.TaskFinalized do
  @moduledoc "Publishes a persisted terminal coding result to the coordinator."

  use Jido.Signal,
    type: "ouroboros.team.task.finalized",
    default_source: "/ouroboros/team",
    schema: [
      delegation_id: [type: :string, required: true],
      worker_id: [type: :string, required: true],
      status: [type: :atom, required: true],
      result: [type: :any, default: nil],
      error: [type: :any, default: nil]
    ]
end
