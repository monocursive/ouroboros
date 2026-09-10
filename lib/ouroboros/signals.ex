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
