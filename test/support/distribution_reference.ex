defmodule Ouroboros.Capability.DistributionReference do
  @moduledoc """
  A mesh agent that exists to be placed on another node.

  Compiled into the test build's `ebin`, which is what makes it reachable from an OS peer
  started with this VM's code path: `Ouroboros.Mesh.start_agent_on/3` is an `:erpc` into
  the peer's own `start_agent/2`, and the module has to be loadable there.

  It routes `ouroboros.agent.message` to `Ouroboros.Mesh.ReceiveMessage` and does nothing
  else, so `test/distribution_test.exs` measures the distribution and not an agent.
  """

  use Jido.Agent,
    name: "ouroboros_capability_distribution_reference",
    description: "A mesh agent whose whole behaviour is the mesh's message convention",
    schema: [
      role: [type: :any, default: nil],
      objective: [type: :any, default: nil],
      inbox: [type: :list, default: []],
      last_message: [type: :any, default: nil],
      messages_received: [type: :non_neg_integer, default: 0]
    ],
    signal_routes: [
      {"ouroboros.agent.message", Ouroboros.Mesh.ReceiveMessage}
    ]

  def actions, do: super() ++ [Ouroboros.Mesh.ReceiveMessage]
end
