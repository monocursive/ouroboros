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

# Effect signals. Every one of them carries `from`, and no handler believes it: the
# acting principal is read from the receiving agent's own server-side identity, and
# `from` is recorded only as the claim it is. See `Ouroboros.Agent.Effects`.

defmodule Ouroboros.Signals.EffectStartAgent do
  @moduledoc "Asks an agent to start another mesh agent, if it is granted `:start_agent`."

  use Jido.Signal,
    type: "ouroboros.agent.effect.start_agent",
    default_source: "/ouroboros/effects",
    schema: [
      from: [type: :string, required: true],
      agent_id: [type: :string, required: true],
      module: [type: :atom, required: true],
      role: [type: :any, default: nil],
      objective: [type: :any, default: nil],
      initial_state: [type: :map, default: %{}]
    ]
end

defmodule Ouroboros.Signals.EffectStopAgent do
  @moduledoc "Asks an agent to stop a mesh agent, if it is granted `:stop_agent`."

  use Jido.Signal,
    type: "ouroboros.agent.effect.stop_agent",
    default_source: "/ouroboros/effects",
    schema: [
      from: [type: :string, required: true],
      agent_id: [type: :string, required: true]
    ]
end

defmodule Ouroboros.Signals.EffectSendMessage do
  @moduledoc "Asks an agent to message another agent, if it is granted `:send_message`."

  use Jido.Signal,
    type: "ouroboros.agent.effect.send_message",
    default_source: "/ouroboros/effects",
    schema: [
      from: [type: :string, required: true],
      to: [type: :string, required: true],
      body: [type: :any, required: true]
    ]
end

defmodule Ouroboros.Signals.EffectDelegateTask do
  @moduledoc "Asks an agent to delegate through a team, if it is granted `:delegate`."

  use Jido.Signal,
    type: "ouroboros.agent.effect.delegate",
    default_source: "/ouroboros/effects",
    schema: [
      from: [type: :string, required: true],
      team: [type: :string, required: true],
      worker_id: [type: :string, required: true],
      objective: [type: :string, required: true],
      options: [type: :keyword_list, default: []]
    ]
end

defmodule Ouroboros.Signals.EffectForgeCapability do
  @moduledoc "Asks an agent to forge a capability from source, if it is granted `:forge`."

  use Jido.Signal,
    type: "ouroboros.agent.effect.forge",
    default_source: "/ouroboros/effects",
    schema: [
      from: [type: :string, required: true],
      module: [type: :atom, required: true],
      source: [type: :string, required: true],
      test_source: [type: :any, default: nil],
      nodes: [type: {:list, :atom}, default: []],
      signer_id: [type: :any, default: nil]
    ]
end

defmodule Ouroboros.Signals.EffectDeployCapability do
  @moduledoc "Asks an agent to deploy a forged artifact, if it is granted `:deploy`."

  use Jido.Signal,
    type: "ouroboros.agent.effect.deploy",
    default_source: "/ouroboros/effects",
    schema: [
      from: [type: :string, required: true],
      artifact_id: [type: :string, required: true],
      nodes: [type: {:list, :atom}, default: []]
    ]
end

defmodule Ouroboros.Signals.EffectSettled do
  @moduledoc """
  Reports the outcome of an effect back to the agent that requested it.

  This is the completion half of an effect, cast by the bounded runner that executed it.
  It is a bookkeeping signal: it can settle an effect the agent already has in flight and
  it can append a refusal, and it can do nothing else.
  """

  use Jido.Signal,
    type: "ouroboros.agent.effect.settled",
    default_source: "/ouroboros/effects",
    schema: [
      effect_id: [type: :string, required: true],
      effect: [type: :atom, required: true],
      status: [type: :atom, required: true],
      principal: [type: :any, default: nil],
      claimed_from: [type: :any, default: nil],
      attempt: [type: :map, default: %{}],
      authority: [type: :map, default: %{}],
      cause: [type: :map, default: %{}],
      result: [type: :any, default: nil],
      error: [type: :any, default: nil]
    ]
end
